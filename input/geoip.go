package input

import (
	"fmt"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/metacubex/meta-rules-converter/output/meta"
	"github.com/metacubex/meta-rules-converter/output/sing"

	"google.golang.org/protobuf/proto"
	"gopkg.in/yaml.v3"

	"github.com/metacubex/mihomo/component/geodata/router"
	"github.com/spf13/cobra"
)

type Rule struct {
	Version int      `json:"version"`
	Rules   []IPRule `json:"rules"`
}

type IPRule struct {
	IPCIDR []string `json:"ip_cidr"`
}

func ConvertIP(cmd *cobra.Command, inPath string, outType string, outDir string) error {
	if inPath == "" {
		inPath = "geoip.dat"
	}
	if outDir == "" {
		outDir = "geoip"
	}
	if outType == "" {
		outType = "clash"
	}
	outDir = strings.TrimSuffix(outDir, "/")
	data, err := os.ReadFile(inPath)
	if err != nil {
		return err
	}
	os.MkdirAll(outDir, 0777)

	var (
		wg    sync.WaitGroup
		mutex sync.Mutex
	)
	countryCIDRs := make(map[string][]string)

	list := router.GeoIPList{}
	err = proto.Unmarshal(data, &list)
	if err != nil {
		return err
	}
	for _, entry := range list.Entry {
		wg.Add(1)
		go func(entry *router.GeoIP) {
			defer wg.Done()
			code := strings.ToLower(entry.CountryCode)
			var results []string
			for _, cidr := range entry.Cidr {
				results = append(results, fmt.Sprintf("%s/%d", net.IP(cidr.Ip).String(), cidr.Prefix))
			}
			mutex.Lock()
			countryCIDRs[code] = results
			mutex.Unlock()
		}(entry)
	}
	wg.Wait()

	switch outType {
	case "clash":
		for code, cidrs := range countryCIDRs {
			ipcidrMap := map[string][]string{
				"payload": cidrs,
			}
			ipcidrOut, err := yaml.Marshal(&ipcidrMap)
			if err != nil {
				fmt.Println(code, " coding err: ", err)
			}
			err = os.WriteFile(outDir+"/"+code+".yaml", ipcidrOut, 0666)
			if err != nil {
				fmt.Println(code, " output err: ", err)
			}
			ipcidrOut = []byte(strings.Join(cidrs, "\n"))
			err = os.WriteFile(outDir+"/"+code+".list", ipcidrOut, 0666)
			if err != nil {
				fmt.Println(code, " output err: ", err)
			}
			err = meta.SaveMetaRuleSet(ipcidrOut, "ipcidr", "text", outDir+"/"+code+".mrs")
			if err != nil {
				fmt.Println(code, " output err: ", err)
			}
		}
	case "sing-box":
		for code, cidrs := range countryCIDRs {
			ipcidrRule := []sing.DefaultHeadlessRule{
				{
					IPCIDR: cidrs,
				},
			}
			err = sing.SaveSingRuleSet(ipcidrRule, outDir+"/"+code)
			if err != nil {
				fmt.Println(code, " output err: ", err)
			}
		}
	}
	return nil
}
