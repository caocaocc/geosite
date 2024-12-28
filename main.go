package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/google/go-github/v45/github"
	"github.com/sagernet/sing-box/common/geosite"
	"github.com/sagernet/sing-box/common/srs"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"

	"github.com/v2fly/v2ray-core/v5/app/router/routercommon"
	"google.golang.org/protobuf/proto"
)

// --------------------------- 全局 githubClient & init ---------------------------

var githubClient *github.Client

func init() {
	accessToken, loaded := os.LookupEnv("ACCESS_TOKEN")
	if !loaded {
		githubClient = github.NewClient(nil)
		return
	}
	transport := &github.BasicAuthTransport{
		Username: accessToken,
	}
	githubClient = github.NewClient(transport.Client())
}

// ------------------------------ 下载/校验相关 ------------------------------

func fetch(from string) (*github.RepositoryRelease, error) {
	names := strings.SplitN(from, "/", 2)
	latestRelease, _, err := githubClient.Repositories.GetLatestRelease(context.Background(), names[0], names[1])
	if err != nil {
		return nil, err
	}
	return latestRelease, err
}

func get(downloadURL *string) ([]byte, error) {
	log.Info("download ", *downloadURL)
	response, err := http.Get(*downloadURL)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	return io.ReadAll(response.Body)
}

func download(release *github.RepositoryRelease) ([]byte, error) {
	geositeAsset := common.Find(release.Assets, func(it *github.ReleaseAsset) bool {
		return *it.Name == "geosite.dat"
	})
	geositeChecksumAsset := common.Find(release.Assets, func(it *github.ReleaseAsset) bool {
		return *it.Name == "geosite.dat.sha256sum"
	})
	if geositeAsset == nil {
		return nil, E.New("geosite asset not found in upstream release ", release.GetName())
	}
	if geositeChecksumAsset == nil {
		return nil, E.New("geosite checksum asset not found in upstream release ", release.GetName())
	}

	data, err := get(geositeAsset.BrowserDownloadURL)
	if err != nil {
		return nil, err
	}
	remoteChecksum, err := get(geositeChecksumAsset.BrowserDownloadURL)
	if err != nil {
		return nil, err
	}

	checksum := sha256.Sum256(data)
	localHash := hex.EncodeToString(checksum[:])
	remoteHash := string(remoteChecksum[:64]) // 假设前 64 字符就是 hex
	if localHash != remoteHash {
		return nil, E.New("checksum mismatch: local=", localHash, " remote=", remoteHash)
	}

	return data, nil
}

// ------------------------------ 解析/过滤/合并相关 ------------------------------

func parse(vGeositeData []byte) (map[string][]geosite.Item, error) {
	vGeositeList := routercommon.GeoSiteList{}
	err := proto.Unmarshal(vGeositeData, &vGeositeList)
	if err != nil {
		return nil, err
	}
	domainMap := make(map[string][]geosite.Item)
	for _, vGeositeEntry := range vGeositeList.Entry {
		code := strings.ToLower(vGeositeEntry.CountryCode)
		domains := make([]geosite.Item, 0, len(vGeositeEntry.Domain)*2)
		attributes := make(map[string][]*routercommon.Domain)

		for _, domain := range vGeositeEntry.Domain {
			// 如果有 attribute，就先记录
			if len(domain.Attribute) > 0 {
				for _, attribute := range domain.Attribute {
					attributes[attribute.Key] = append(attributes[attribute.Key], domain)
				}
			}

			switch domain.Type {
			case routercommon.Domain_Plain:
				domains = append(domains, geosite.Item{
					Type:  geosite.RuleTypeDomainKeyword,
					Value: domain.Value,
				})
			case routercommon.Domain_Regex:
				domains = append(domains, geosite.Item{
					Type:  geosite.RuleTypeDomainRegex,
					Value: domain.Value,
				})
			case routercommon.Domain_RootDomain:
				if strings.Contains(domain.Value, ".") {
					domains = append(domains, geosite.Item{
						Type:  geosite.RuleTypeDomain,
						Value: domain.Value,
					})
				}
				domains = append(domains, geosite.Item{
					Type:  geosite.RuleTypeDomainSuffix,
					Value: "." + domain.Value,
				})
			case routercommon.Domain_Full:
				domains = append(domains, geosite.Item{
					Type:  geosite.RuleTypeDomain,
					Value: domain.Value,
				})
			}
		}
		domainMap[code] = common.Uniq(domains)

		// 把每个 attribute 都做成额外的 code
		for attr, attrDomains := range attributes {
			attributeDomains := make([]geosite.Item, 0, len(attrDomains)*2)
			for _, domain := range attrDomains {
				switch domain.Type {
				case routercommon.Domain_Plain:
					attributeDomains = append(attributeDomains, geosite.Item{
						Type:  geosite.RuleTypeDomainKeyword,
						Value: domain.Value,
					})
				case routercommon.Domain_Regex:
					attributeDomains = append(attributeDomains, geosite.Item{
						Type:  geosite.RuleTypeDomainRegex,
						Value: domain.Value,
					})
				case routercommon.Domain_RootDomain:
					if strings.Contains(domain.Value, ".") {
						attributeDomains = append(attributeDomains, geosite.Item{
							Type:  geosite.RuleTypeDomain,
							Value: domain.Value,
						})
					}
					attributeDomains = append(attributeDomains, geosite.Item{
						Type:  geosite.RuleTypeDomainSuffix,
						Value: "." + domain.Value,
					})
				case routercommon.Domain_Full:
					attributeDomains = append(attributeDomains, geosite.Item{
						Type:  geosite.RuleTypeDomain,
						Value: domain.Value,
					})
				}
			}
			domainMap[code+"@"+attr] = common.Uniq(attributeDomains)
		}
	}

	return domainMap, nil
}

type filteredCodePair struct {
	code    string
	badCode string
}

// filterTags 和 mergeTags 的逻辑原封不动
func filterTags(data map[string][]geosite.Item) {
	var codeList []string
	for code := range data {
		codeList = append(codeList, code)
	}
	var badCodeList []filteredCodePair
	var filteredCodeMap []string
	var mergedCodeMap []string
	for _, code := range codeList {
		codeParts := strings.Split(code, "@")
		if len(codeParts) != 2 {
			continue
		}
		leftParts := strings.Split(codeParts[0], "-")
		var lastName string
		if len(leftParts) > 1 {
			lastName = leftParts[len(leftParts)-1]
		}
		if lastName == "" {
			lastName = codeParts[0]
		}
		if lastName == codeParts[1] {
			delete(data, code)
			filteredCodeMap = append(filteredCodeMap, code)
			continue
		}
		if "!"+lastName == codeParts[1] {
			badCodeList = append(badCodeList, filteredCodePair{
				code:    codeParts[0],
				badCode: code,
			})
		} else if lastName == "!"+codeParts[1] {
			badCodeList = append(badCodeList, filteredCodePair{
				code:    codeParts[0],
				badCode: code,
			})
		}
	}
	for _, it := range badCodeList {
		badList := data[it.badCode]
		if badList == nil {
			panic("bad list not found: " + it.badCode)
		}
		delete(data, it.badCode)
		newMap := make(map[geosite.Item]bool)
		for _, item := range data[it.code] {
			newMap[item] = true
		}
		for _, item := range badList {
			delete(newMap, item)
		}
		newList := make([]geosite.Item, 0, len(newMap))
		for item := range newMap {
			newList = append(newList, item)
		}
		data[it.code] = newList
		mergedCodeMap = append(mergedCodeMap, it.badCode)
	}
	sort.Strings(filteredCodeMap)
	sort.Strings(mergedCodeMap)
	os.Stderr.WriteString("filtered " + strings.Join(filteredCodeMap, ",") + "\n")
	os.Stderr.WriteString("merged " + strings.Join(mergedCodeMap, ",") + "\n")
}

func mergeTags(data map[string][]geosite.Item) {
	var codeList []string
	for code := range data {
		codeList = append(codeList, code)
	}
	var cnCodeList []string
	for _, code := range codeList {
		codeParts := strings.Split(code, "@")
		if len(codeParts) != 2 {
			continue
		}
		if codeParts[1] != "cn" {
			continue
		}
		if !strings.HasPrefix(codeParts[0], "category-") {
			continue
		}
		if strings.HasSuffix(codeParts[0], "-cn") || strings.HasSuffix(codeParts[0], "-!cn") {
			continue
		}
		cnCodeList = append(cnCodeList, code)
	}
	for _, code := range codeList {
		if !strings.HasPrefix(code, "category-") {
			continue
		}
		if !strings.HasSuffix(code, "-cn") {
			continue
		}
		if strings.Contains(code, "@") {
			continue
		}
		cnCodeList = append(cnCodeList, code)
	}
	newMap := make(map[geosite.Item]bool)
	for _, item := range data["geolocation-cn"] {
		newMap[item] = true
	}
	for _, code := range cnCodeList {
		for _, item := range data[code] {
			newMap[item] = true
		}
	}
	newList := make([]geosite.Item, 0, len(newMap))
	for item := range newMap {
		newList = append(newList, item)
	}
	data["geolocation-cn"] = newList
	data["cn"] = append(newList, geosite.Item{
		Type:  geosite.RuleTypeDomainSuffix,
		Value: "cn",
	})
	println("merged cn categories: " + strings.Join(cnCodeList, ","))
}

// ------------------------------ 新增三种格式的转换函数 ------------------------------

// List 格式（假设类似 Surge 的写法），例：DOMAIN-SUFFIX,apple.com
func convertListRule(item geosite.Item, _ string) (string, bool) {
	switch item.Type {
	case geosite.RuleTypeDomainSuffix:
		// 自动去掉开头的 .
		val := strings.TrimPrefix(item.Value, ".")
		return "DOMAIN-SUFFIX," + val, true
	case geosite.RuleTypeDomain:
		val := strings.TrimPrefix(item.Value, ".")
		return "DOMAIN," + val, true
	case geosite.RuleTypeDomainKeyword:
		return "DOMAIN-KEYWORD," + item.Value, true
	case geosite.RuleTypeDomainRegex:
		// 如果没有原生的正则域名，可以用 URL-REGEX（或忽略）
		return "URL-REGEX," + item.Value, true
	default:
		return "", false
	}
}

// YAML 格式（假设类似 Clash 的写法），例：DOMAIN-SUFFIX,apple.com,Proxy
// 这里的 policy 可以随便填，比如 "Proxy"；也可以不加
func convertYamlRule(item geosite.Item, policy string) (string, bool) {
	switch item.Type {
	case geosite.RuleTypeDomainSuffix:
		val := strings.TrimPrefix(item.Value, ".")
		return "DOMAIN-SUFFIX," + val + "," + policy, true
	case geosite.RuleTypeDomain:
		val := strings.TrimPrefix(item.Value, ".")
		return "DOMAIN," + val + "," + policy, true
	case geosite.RuleTypeDomainKeyword:
		return "DOMAIN-KEYWORD," + item.Value + "," + policy, true
	case geosite.RuleTypeDomainRegex:
		return "DOMAIN-REGEX," + item.Value + "," + policy, true
	default:
		return "", false
	}
}

// TXT 格式，按照原来带 . 的逻辑输出
// 例：domainSuffix = .apple.com -> ".apple.com"
func convertTxtRule(item geosite.Item, _ string) (string, bool) {
	switch item.Type {
	case geosite.RuleTypeDomainSuffix:
		return item.Value, true // 原样输出，例如 ".apple.com"
	case geosite.RuleTypeDomain:
		return item.Value, true // 例如 "apple.com" (如果原本带了 . 就保留)
	case geosite.RuleTypeDomainKeyword:
		// 没有点的概念，这里可以按需求定。简单输出就行
		return item.Value, true
	case geosite.RuleTypeDomainRegex:
		// 原本正则写法可以直接保留
		return item.Value, true
	default:
		return "", false
	}
}

// ------------------------------ 写文件的辅助函数 ------------------------------

// writeRules 将 domainMap 转换为指定格式（通过 convertFunc ），
// 然后写到同一个目录里，文件名：geosite-<code><ext>
func writeRules(
	domainMap map[string][]geosite.Item,
	dir string,
	ext string,
	policy string,
	convertFunc func(item geosite.Item, policy string) (string, bool),
) error {
	for code, items := range domainMap {
		var lines []string
		for _, it := range items {
			line, ok := convertFunc(it, policy)
			if ok && line != "" {
				lines = append(lines, line)
			}
		}
		if len(lines) == 0 {
			continue
		}
		filename := filepath.Join(dir, "geosite-"+code+ext)
		err := os.WriteFile(filename, []byte(strings.Join(lines, "\n")), 0644)
		if err != nil {
			return err
		}
	}
	return nil
}

// ------------------------------ generate 函数 ------------------------------

func generate(release *github.RepositoryRelease, output string, cnOutput string, ruleSetOutput string, ruleSetUnstableOutput string) error {
	// 1. 下载 geosite.dat
	vData, err := download(release)
	if err != nil {
		return err
	}
	// 2. 解析
	domainMap, err := parse(vData)
	if err != nil {
		return err
	}
	// 3. 过滤 & 合并
	filterTags(domainMap)
	mergeTags(domainMap)

	// --- 以下是原有逻辑，写 geosite.db / geosite-cn.db ---
	outputPath, _ := filepath.Abs(output)
	os.Stderr.WriteString("write " + outputPath + "\n")

	outputFile, err := os.Create(output)
	if err != nil {
		return err
	}
	defer outputFile.Close()
	writer := bufio.NewWriter(outputFile)
	err = geosite.Write(writer, domainMap)
	if err != nil {
		return err
	}
	err = writer.Flush()
	if err != nil {
		return err
	}

	// 写 geosite-cn.db
	cnCodes := []string{"geolocation-cn"}
	cnDomainMap := make(map[string][]geosite.Item)
	for _, cnCode := range cnCodes {
		cnDomainMap[cnCode] = domainMap[cnCode]
	}
	cnOutputFile, err := os.Create(cnOutput)
	if err != nil {
		return err
	}
	defer cnOutputFile.Close()
	writer.Reset(cnOutputFile)
	err = geosite.Write(writer, cnDomainMap)
	if err != nil {
		return err
	}
	err = writer.Flush()
	if err != nil {
		return err
	}

	// 先清理后重建 ruleSetOutput / ruleSetUnstableOutput 目录
	os.RemoveAll(ruleSetOutput)
	os.RemoveAll(ruleSetUnstableOutput)
	err = os.MkdirAll(ruleSetOutput, 0o755)
	if err != nil {
		return err
	}
	err = os.MkdirAll(ruleSetUnstableOutput, 0o755)
	if err != nil {
		return err
	}

	// 4. 原先写 .srs 的逻辑
	for code, domains := range domainMap {
		var headlessRule option.DefaultHeadlessRule
		defaultRule := geosite.Compile(domains)
		headlessRule.Domain = defaultRule.Domain
		headlessRule.DomainSuffix = defaultRule.DomainSuffix
		headlessRule.DomainKeyword = defaultRule.DomainKeyword
		headlessRule.DomainRegex = defaultRule.DomainRegex

		var plainRuleSet option.PlainRuleSet
		plainRuleSet.Rules = []option.HeadlessRule{
			{
				Type:           C.RuleTypeDefault,
				DefaultOptions: headlessRule,
			},
		}

		srsPath := filepath.Join(ruleSetOutput, "geosite-"+code+".srs")
		unstableSRSPath := filepath.Join(ruleSetUnstableOutput, "geosite-"+code+".srs")

		outputRuleSet, err := os.Create(srsPath)
		if err != nil {
			return err
		}
		err = srs.Write(outputRuleSet, plainRuleSet, false)
		outputRuleSet.Close()
		if err != nil {
			return err
		}
		outputRuleSetUnstable, err := os.Create(unstableSRSPath)
		if err != nil {
			return err
		}
		err = srs.Write(outputRuleSetUnstable, plainRuleSet, true)
		outputRuleSetUnstable.Close()
		if err != nil {
			return err
		}
	}

	// 5. 额外生成三种格式 (.list, .yml, .txt)，同样写在 ruleSetOutput 目录下
	// 你可根据需要改路径、后缀、规则等
	if err := writeRules(domainMap, ruleSetOutput, ".list", "", convertListRule); err != nil {
		return err
	}
	if err := writeRules(domainMap, ruleSetOutput, ".yml", "", convertYamlRule); err != nil {
		return err
	}
	if err := writeRules(domainMap, ruleSetOutput, ".txt", "", convertTxtRule); err != nil {
		return err
	}

	return nil
}

// ------------------------------ release & main ------------------------------

func setActionOutput(name string, content string) {
	os.Stdout.WriteString("::set-output name=" + name + "::" + content + "\n")
}

func release(source string, destination string, output string, cnOutput string, ruleSetOutput string, ruleSetOutputUnstable string) error {
	sourceRelease, err := fetch(source)
	if err != nil {
		return err
	}
	destinationRelease, err := fetch(destination)
	if err != nil {
		log.Warn("missing destination latest release")
	} else {
		if os.Getenv("NO_SKIP") != "true" && strings.Contains(destinationRelease.GetName(), sourceRelease.GetName()) {
			log.Info("already latest")
			setActionOutput("skip", "true")
			return nil
		}
	}
	err = generate(sourceRelease, output, cnOutput, ruleSetOutput, ruleSetOutputUnstable)
	if err != nil {
		return err
	}
	setActionOutput("tag", sourceRelease.GetName())
	return nil
}

func main() {
	err := release(
		"caocaocc/domain-list-custom",
		"caocaocc/geosite",
		"geosite.db",
		"geosite-cn.db",
		"rule-set",
		"rule-set-unstable",
	)
	if err != nil {
		log.Fatal(err)
	}
}
