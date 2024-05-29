package main

import (
	"edu.ncsu.lib/logparse/v2/internal/apache"
	"edu.ncsu.lib/logparse/v2/internal/util"
	//"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"
)

type OutputEncoder interface {
	Encode(interface{}) error
}

type InterestingRequest struct {
	IP        string `json:"ipv4"`
	Source    string `json:"source"`
	Range     string `json:"range"`
	Request   string `json:"query_string"`
	UserAgent string `json:"user_agent"`
	UASummary string `json:"user_agent_summary"`
	Time      time.Time
}

func showWhoisinfo(line apache.Line) {
	whois, err := util.IPV4Search(line.RemoteHost)
	if err != nil {
		panic(err)
	}
	wi, err := util.ParseWhois(whois)
	if err == nil {
		fmt.Println(wi)
	} else {
		fmt.Println(err)
	}
}

func main() {
	var ipFile string
	format := "json"

	flag.StringVar(&ipFile, "b", "", "path to file for blocklist")
	flag.StringVar(&format, "f", "json", "output format")
	var cl *util.CIDRClassifier
	var err error

	flag.Parse()
	if ipFile == "" {
		cl = util.NewDefaultClassifier()
	} else {
		cl, err = util.NewClassifier(ipFile)
		if err != nil {
			wrap := fmt.Errorf("Unable to load blocklist file %s: %s",
				ipFile,
				err)
			panic(wrap)

		}
	}

	fn := "/dev/stdin"
	if len(flag.Args()) > 0 {
		fn = flag.Args()[0]
	}
	p, err := apache.NewParser()
	if err != nil {
		panic(err)
	}
	reader, err := p.Read(fn)
	if err != nil {
		panic(err)
	}

	encoder := json.NewEncoder(os.Stdout)
	for rec := range reader {
		if rec.Error == nil {
			line := rec.Line
			if ok, ip_range := cl.Contains(line.RemoteHost); ok {
				rec := &InterestingRequest{
					line.RemoteHost,
					ip_range.Owner,
					ip_range.Range,
					line.URL,
					line.UserAgent,
					util.SummarizeUserAgent(line.UserAgent),
					line.Time}
				encoder.Encode(rec)
			}

		}
	}
}
