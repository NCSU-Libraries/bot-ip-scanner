package util

import (
    _ "embed"
    "fmt"
    "os"
    "github.com/3th1nk/cidr"
    "gopkg.in/yaml.v3"
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

func LoadRanges(yamlContent []byte) (*BanList) {
    banList := BanList{}
    err := yaml.Unmarshal(yamlContent, &banList)
    if err != nil {
        panic(err)
    }
    return &banList
}

func NewClassifier(path string) (*CIDRClassifier, error) {
    yamlContent, err := os.ReadFile(path)
    if err != nil {
        return &CIDRClassifier{}, err
    }
    bl := LoadRanges(yamlContent)
    return BuildClassifier(bl), nil
}

func BuildClassifier(bl *BanList) (*CIDRClassifier) {
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

//go:embed princeton_ban_list.yml
var defaultYaml []byte
func NewDefaultClassifier() (*CIDRClassifier) {
    bl := LoadRanges(defaultYaml)
    return BuildClassifier(bl)
}
