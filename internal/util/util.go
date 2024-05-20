package util

import (
    "fmt"
    "github.com/3th1nk/cidr"
    "gopkg.in/yaml.v3"
    _ "embed"
)

type IPRange struct {
    Range string
    cidr_range *cidr.CIDR 
    Owner string
    Location string
}

type CIDRClassifier struct {
    ranges []*IPRange
    cache map[string]*IPRange
    seen map[string]bool
}

func (c *CIDRClassifier) Contains(ip_address string) (bool, *IPRange) {
    if ip_range, ok := c.cache[ip_address]; ok {
        return true, ip_range
    }
    if _, ok := c.seen[ip_address]; ok {
        return false, nil
    }
    for _, ip_range := range(c.ranges) {
        if ip_range.cidr_range.Contains(ip_address) {
            c.cache[ip_address] = ip_range
            return true, ip_range
        }
    }
    c.seen[ip_address] = false
    return false, nil
}

type BanGroup struct {
    Name string `yaml:"name"`
    Ranges []string `yaml:"ip_range"`
}

func(g *BanGroup) String() string {
    return fmt.Sprintf("[%s] %s", g.Name, g.Ranges)
}

type BanList struct {
    Groups []*BanGroup `yaml:"banned_ranges"`
}

//go:embed princeton_ban_list.yml
var defaultYaml string

func LoadRanges() (*BanList) {
    banList := BanList{}
    err := yaml.Unmarshal([]byte(defaultYaml), &banList)
    if err != nil {
        panic(err)
    }
    return &banList
}

func NewPrincetonClassifier() (*CIDRClassifier) {
    bl := LoadRanges()
    populated := []*IPRange{}
    for _, group := range bl.Groups {
        for _, spec := range(group.Ranges) {
            cidr_range, err := cidr.Parse(spec)
            if err != nil {
                panic(err)
            }
            populated = append(populated, &IPRange{spec, cidr_range, group.Name, "Wherever"})
        }
    }
    c := &CIDRClassifier{populated, make(map[string]*IPRange), make(map[string]bool) }
    return c
}
 
func NewTencentClassifier() (*CIDRClassifier) {
    ranges := []string {
      "42.187.0.0/32",
      "42.192.0.0/16",
      "42.193.0.0/32",
      "42.194.0.0/32",
      "43.128.0.0/13",
      "43.153.0.0/16",
      "43.156.0.0/16",
      "43.163.3.166/32",
      "43.163.5.194/32",
      "45.40.0.0/32",
      "49.51.0.0/32",
      "49.232.0.0/15",
      "49.234.0.0/16",
      "49.235.0.0/32",
      "58.87.0.0/32",
      "62.234.0.0/32",
      "81.68.0.0/15",
      "81.70.0.0/16",
      "81.71.0.0/32",
      "82.156.0.0/16",
      "82.157.0.0/32",
      "101.244.0.0/32",
      "101.32.0.0/32",
      "101.33.0.0/32",
      "103.95.0.0/32",
      "103.234.0.0/32",
      "106.52.0.0/32",
      "106.55.0.0/32",
      "109.244.0.0/32",
      "111.229.0.0/32",
      "111.230.0.0/16",
      "111.231.0.0/32",
      "114.132.0.0/32",
      "115.159.0.0/32",
      "118.126.0.0/32",
      "118.195.0.0/32",
      "118.24.0.0/16",
      "118.25.0.0/32",
      "118.89.0.0/32",
      "119.27.0.0/32",
      "119.28.0.0/16",
      "119.29.0.0/32",
      "119.45.0.0/32",
      "121.4.0.0/16",
      "121.5.0.0/32",
      "122.152.0.0/32",
      "123.206.0.0/16",
      "123.207.0.0/32",
      "124.156.0.0/32",
      "124.220.0.0/15",
      "124.222.0.0/16",
      "124.223.0.0/32",
      "128.108.0.0/32",
      "129.28.0.0/32",
      "129.204.0.0/32",
      "129.211.0.0/32",
      "129.226.0.0/32",
      "132.232.0.0/32",
      "134.175.0.0/32",
      "139.155.0.0/32",
      "139.186.0.0/32",
      "139.199.0.0/32",
      "140.143.0.0/32",
      "146.56.0.0/32",
      "148.70.0.0/32",
      "150.109.0.0/32",
      "150.158.0.0/32",
      "152.136.0.0/32",
      "154.8.0.0/32",
      "159.14.0.0/32",
      "162.14.0.0/32",
      "162.62.0.0/32",
      "170.106.0.0/16",
      "172.81.0.0/32",
      "175.24.0.0/32",
      "175.27.0.0/32",
      "175.178.0.0/32",
      "182.254.0.0/32",
      "188.131.0.0/32",
      "192.144.0.0/32",
      "193.112.0.0/32",
      "203.195.0.0/32",
      "210.73.0.0/32",
      "211.159.0.0/32",
      "212.64.0.0/32",
      "212.129.0.0/32"}
    populated := []*IPRange{}
    for _, spec := range ranges {
        cidr_range, err := cidr.Parse(spec)
        if err != nil {
            panic(err)
        }
        populated = append(populated, &IPRange{spec, cidr_range, "Tencent", "Wherever"})
    }
    c := &CIDRClassifier{populated, make(map[string]*IPRange), make(map[string]bool) }
    return c
}

