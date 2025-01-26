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

	"github.com/sagernet/sing-box/common/geosite"
	"github.com/sagernet/sing-box/common/srs"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"

	"github.com/google/go-github/v45/github"
	"github.com/v2fly/v2ray-core/v5/app/router/routercommon"
	"google.golang.org/protobuf/proto"
)

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
		return nil, E.New("geosite asset not found in upstream release ", release.Name)
	}
	if geositeChecksumAsset == nil {
		return nil, E.New("geosite asset not found in upstream release ", release.Name)
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
	if hex.EncodeToString(checksum[:]) != string(remoteChecksum[:64]) {
		return nil, E.New("checksum mismatch")
	}
	return data, nil
}

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
				domains = append(domains, geosite.Item{
					Type:  geosite.RuleTypeDomainSuffix,
					Value: domain.Value,
				})
			case routercommon.Domain_Full:
				domains = append(domains, geosite.Item{
					Type:  geosite.RuleTypeDomain,
					Value: domain.Value,
				})
			}
		}
		domainMap[code] = common.Uniq(domains)
		for attribute, attributeEntries := range attributes {
			attributeDomains := make([]geosite.Item, 0, len(attributeEntries)*2)
			for _, domain := range attributeEntries {
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
					attributeDomains = append(attributeDomains, geosite.Item{
						Type:  geosite.RuleTypeDomainSuffix,
						Value: domain.Value,
					})
				case routercommon.Domain_Full:
					attributeDomains = append(attributeDomains, geosite.Item{
						Type:  geosite.RuleTypeDomain,
						Value: domain.Value,
					})
				}
			}
			domainMap[code+"@"+attribute] = common.Uniq(attributeDomains)
		}
	}
	return domainMap, nil
}

type filteredCodePair struct {
	code    string
	badCode string
}

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
	os.Stderr.WriteString("merged cn categories: " + strings.Join(cnCodeList, ",") + "\n")
}

func generate(release *github.RepositoryRelease, output string, cnOutput string, ruleSetOutput string, ruleSetUnstableOutput string) error {
	vData, err := download(release)
	if err != nil {
		return err
	}
	domainMap, err := parse(vData)
	if err != nil {
		return err
	}
	filterTags(domainMap)
	mergeTags(domainMap)
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
	cnCodes := []string{
		"geolocation-cn",
	}
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
	os.RemoveAll(ruleSetOutput)
	os.RemoveAll(ruleSetUnstableOutput)
	err = os.MkdirAll(ruleSetOutput, 0o755)
	err = os.MkdirAll(ruleSetUnstableOutput, 0o755)
	if err != nil {
		return err
	}
	for code, domains := range domainMap {
		err = generateFiles(code, domains, ruleSetOutput, ruleSetUnstableOutput)
		if err != nil {
			return err
		}
	}
	return nil
}

func generateFiles(code string, domains []geosite.Item, ruleSetOutput string, ruleSetUnstableOutput string) error {
	// Sort domains
	sort.Slice(domains, func(i, j int) bool {
		if domains[i].Type != domains[j].Type {
			return domains[i].Type < domains[j].Type
		}
		return domains[i].Value < domains[j].Value
	})

	// Generate SRS file
	err := generateSRSFile(code, domains, ruleSetOutput, ruleSetUnstableOutput)
	if err != nil {
		return err
	}

	// Generate TXT file
	err = generateTXTFile(code, domains, ruleSetOutput, ruleSetUnstableOutput)
	if err != nil {
		return err
	}

	// Generate LIST file
	err = generateLISTFile(code, domains, ruleSetOutput, ruleSetUnstableOutput)
	if err != nil {
		return err
	}

	// Generate YAML file
	err = generateYAMLFile(code, domains, ruleSetOutput, ruleSetUnstableOutput)
	if err != nil {
		return err
	}

	// Generate SNIPPET file
	err = generateSNIPPETFile(code, domains, ruleSetOutput, ruleSetUnstableOutput)
	if err != nil {
		return err
	}

	return nil
}

func generateSRSFile(code string, domains []geosite.Item, ruleSetOutput string, ruleSetUnstableOutput string) error {
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
	defer outputRuleSet.Close()
	err = srs.Write(outputRuleSet, plainRuleSet, false)
	if err != nil {
		return err
	}

	outputRuleSetUnstable, err := os.Create(unstableSRSPath)
	if err != nil {
		return err
	}
	defer outputRuleSetUnstable.Close()
	err = srs.Write(outputRuleSetUnstable, plainRuleSet, true)
	if err != nil {
		return err
	}

	return nil
}

func generateTXTFile(code string, domains []geosite.Item, ruleSetOutput string, ruleSetUnstableOutput string) error {
	txtPath := filepath.Join(ruleSetOutput, "geosite-"+code+".txt")
	unstableTXTPath := filepath.Join(ruleSetUnstableOutput, "geosite-"+code+".txt")

	txtFile, err := os.Create(txtPath)
	if err != nil {
		return err
	}
	defer txtFile.Close()
	txtWriter := bufio.NewWriter(txtFile)

	unstableTXTFile, err := os.Create(unstableTXTPath)
	if err != nil {
		return err
	}
	defer unstableTXTFile.Close()
	unstableTXTWriter := bufio.NewWriter(unstableTXTFile)

	for _, domain := range domains {
		var line string
		switch domain.Type {
		case geosite.RuleTypeDomain:
			line = domain.Value + "\n"
		case geosite.RuleTypeDomainSuffix:
			line = "+." + domain.Value + "\n"
		case geosite.RuleTypeDomainRegex:
			// Only write to unstable file
			_, err = unstableTXTWriter.WriteString(domain.Value + "\n")
			if err != nil {
				return err
			}
			continue
		default:
			continue
		}
		_, err = txtWriter.WriteString(line)
		if err != nil {
			return err
		}
		_, err = unstableTXTWriter.WriteString(line)
		if err != nil {
			return err
		}
	}

	err = txtWriter.Flush()
	if err != nil {
		return err
	}
	err = unstableTXTWriter.Flush()
	if err != nil {
		return err
	}

	return nil
}

func generateLISTFile(code string, domains []geosite.Item, ruleSetOutput string, ruleSetUnstableOutput string) error {
    listPath := filepath.Join(ruleSetOutput, "geosite-"+code+".list")
    unstableListPath := filepath.Join(ruleSetUnstableOutput, "geosite-"+code+".list")

    listFile, err := os.Create(listPath)
    if err != nil {
        return err
    }
    defer listFile.Close()
    listWriter := bufio.NewWriter(listFile)

    unstableListFile, err := os.Create(unstableListPath)
    if err != nil {
        return err
    }
    defer unstableListFile.Close()
    unstableListWriter := bufio.NewWriter(unstableListFile)

    for _, domain := range domains {
        var line string
        switch domain.Type {
        case geosite.RuleTypeDomain:
            line = "DOMAIN," + domain.Value + "\n"
        case geosite.RuleTypeDomainSuffix:
            line = "DOMAIN-SUFFIX," + domain.Value + "\n"
        default:
            continue
        }
        _, err = listWriter.WriteString(line)
        if err != nil {
            return err
        }
        _, err = unstableListWriter.WriteString(line)
        if err != nil {
            return err
        }
    }

    err = listWriter.Flush()
    if err != nil {
        return err
    }
    err = unstableListWriter.Flush()
    if err != nil {
        return err
    }

    return nil
}

func generateYAMLFile(code string, domains []geosite.Item, ruleSetOutput string, ruleSetUnstableOutput string) error {
	yamlPath := filepath.Join(ruleSetOutput, "geosite-"+code+".yaml")
	unstableYAMLPath := filepath.Join(ruleSetUnstableOutput, "geosite-"+code+".yaml")

	yamlFile, err := os.Create(yamlPath)
	if err != nil {
		return err
	}
	defer yamlFile.Close()
	yamlWriter := bufio.NewWriter(yamlFile)

	unstableYAMLFile, err := os.Create(unstableYAMLPath)
	if err != nil {
		return err
	}
	defer unstableYAMLFile.Close()
	unstableYAMLWriter := bufio.NewWriter(unstableYAMLFile)

	_, err = yamlWriter.WriteString("payload:\n")
	if err != nil {
		return err
	}
	_, err = unstableYAMLWriter.WriteString("payload:\n")
	if err != nil {
		return err
	}

	for _, domain := range domains {
		var line string
		switch domain.Type {
		case geosite.RuleTypeDomain:
			line = "  - '" + domain.Value + "'\n"
		case geosite.RuleTypeDomainSuffix:
			line = "  - '+." + domain.Value + "'\n"
		case geosite.RuleTypeDomainRegex:
			// Only write to unstable file
			_, err = unstableYAMLWriter.WriteString("  - '" + domain.Value + "'\n")
			if err != nil {
				return err
			}
			continue
		default:
			continue
		}
		_, err = yamlWriter.WriteString(line)
		if err != nil {
			return err
		}
		_, err = unstableYAMLWriter.WriteString(line)
		if err != nil {
			return err
		}
	}

	err = yamlWriter.Flush()
	if err != nil {
		return err
	}
	err = unstableYAMLWriter.Flush()
	if err != nil {
		return err
	}

	return nil
}

func generateSNIPPETFile(code string, domains []geosite.Item, ruleSetOutput string, ruleSetUnstableOutput string) error {
	snippetPath := filepath.Join(ruleSetOutput, "geosite-"+code+".snippet")
	unstableSnippetPath := filepath.Join(ruleSetUnstableOutput, "geosite-"+code+".snippet")

	snippetFile, err := os.Create(snippetPath)
	if err != nil {
		return err
	}
	defer snippetFile.Close()
	snippetWriter := bufio.NewWriter(snippetFile)

	unstableSnippetFile, err := os.Create(unstableSnippetPath)
	if err != nil {
		return err
	}
	defer unstableSnippetFile.Close()
	unstableSnippetWriter := bufio.NewWriter(unstableSnippetFile)

	for _, domain := range domains {
		var line string
		switch domain.Type {
		case geosite.RuleTypeDomain:
			line = "host, " + domain.Value + ", proxy" + "\n"
		case geosite.RuleTypeDomainSuffix:
			line = "host-suffix, " + domain.Value + ", proxy" + "\n"
		default:
			continue
		}
		_, err = snippetWriter.WriteString(line)
		if err != nil {
			return err
		}
		_, err = unstableSnippetWriter.WriteString(line)
		if err != nil {
			return err
		}
	}

	err = snippetWriter.Flush()
	if err != nil {
		return err
	}
	err = unstableSnippetWriter.Flush()
	if err != nil {
		return err
	}

	return nil
}

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
		if os.Getenv("NO_SKIP") != "true" && strings.Contains(*destinationRelease.Name, *sourceRelease.Name) {
			log.Info("already latest")
			setActionOutput("skip", "true")
			return nil
		}
	}
	err = generate(sourceRelease, output, cnOutput, ruleSetOutput, ruleSetOutputUnstable)
	if err != nil {
		return err
	}
	setActionOutput("tag", *sourceRelease.Name)
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
