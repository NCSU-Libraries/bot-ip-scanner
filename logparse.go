package main

import (
	"edu.ncsu.lib/logparse/v2/internal/apache"
	"edu.ncsu.lib/logparse/v2/internal/util"
	"encoding/json"
	//"fmt"
	"os"
	"time"
)

type BannedRequest struct {
	IP        string `json:"ipv4"`
	Source    string `json:"source"`
	Range     string `json:"range"`
	Request   string `json:"query_string"`
	UserAgent string `json:"user_agent"`
	Time      time.Time
}

func main() {
	cl := util.NewPrincetonClassifier()
	fn := os.Args[1]
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
				rec := &BannedRequest{
					line.RemoteHost,
					ip_range.Owner,
					ip_range.Range,
					line.URL,
					line.UserAgent,
					line.Time}
				encoder.Encode(rec)
				//fmt.Printf("[%s] matches (%s) from (%s) requested %s\n", rec.Line.RemoteHost, ip_range.Range, ip_range.Owner, rec.Line.URL)

			}

		}
	}
}
