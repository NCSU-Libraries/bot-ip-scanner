package util

import (
    "fmt"
    "github.com/likexian/whois"
    "net"
    "regexp"
    "time"
)

type WhoisResult struct {
    INetNum []string
    Source string
    EMail string
    AbuseEmail string
    LastModified time.Time
}

func (w *WhoisResult) GetCIDR() (string, bool) {
    return CIDRFromAddresses(w.INetNum[0], w.INetNum[1])
}
        
// inetnum:        43.130.0.0 - 43.130.63.255
var whoisIpRange_rgx = regexp.MustCompile("inetnum:\\s+ (?P<start>\\S+) - (?P<end>\\S+)")
var whoisLastModified_rgx = regexp.MustCompile("last-modified:\\s+(?P<value>\\S+)")
var whoisEmail_rgx = regexp.MustCompile("e-mail:\\s+(?P<value>\\S+@\\S+)")
var whoisAbuse_rgx = regexp.MustCompile("abuse-mailbox:\\s+(?P<value>\\S+@\\S+)")

func MatchesToMap(expr *regexp.Regexp, input string) (map[string]string) {
    matches := expr.FindStringSubmatch(input)
    r := make(map[string]string)
    names := expr.SubexpNames()
    fmt.Println(names)
    for i, name := range(names) {
        r[name] = matches[i]
    }
    return r
}

func ParseWhois(whois string) (WhoisResult, error) {
    ips := MatchesToMap(whoisIpRange_rgx, whois)
    inet_num := []string{ ips["start"], ips["end"] }
    return WhoisResult{INetNum: inet_num}, nil
}



func CIDRFromAddresses(start_addr string, end_addr string) (string, bool) {
    start_ip := net.ParseIP(start_addr)
    end_ip   := net.ParseIP(end_addr)
    maxLen := 32
    for l := maxLen; l >= 0; l-- {
        mask := net.CIDRMask(l, maxLen)
        na := start_ip.Mask(mask)
        n := net.IPNet{IP: na, Mask: mask}
        if n.Contains(end_ip) {
            return fmt.Sprintf("%v/%v", na, l), true
        }
    }
    return "", false
}


func IPV4Search(ip_address string) (string, error) {
    return whois.Whois(ip_address)
}

