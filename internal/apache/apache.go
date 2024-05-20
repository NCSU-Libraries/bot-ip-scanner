package apache

import (
	"bufio"
	"bytes"
    "errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"time"
)

// Line : Represents a line in standard Apache log
type Line struct {
	RemoteHost string
	Time       time.Time
	Request    string
	Status     int
	Bytes      int
	Referer    string
	UserAgent  string
	URL        string
}

type MaybeLine struct {
	Line  *Line
	Error error
}

type Parser struct {
	LineRegexp *regexp.Regexp
	Layout     string
}

func NewParser() (*Parser, error) {
    rgx, err := CompileRegexp()
    if err != nil {
        return nil, err
    }
	return &Parser{rgx, "02/Jan/2006:15:04:05 -0700"}, nil
}

func (p *Parser) Read(path string) (chan *MaybeLine, error) {
	output := make(chan *MaybeLine)

	file, err := os.Open(path)
	if err != nil {
	    return nil, err
	}
    go func() {
	    defer file.Close()
        defer close(output)

	    scanner := bufio.NewScanner(file)
	    for scanner.Scan() {
		    line := scanner.Text()
		    result, err := p.ParseLine(line)
		    output <- &MaybeLine{result, err}
	    }
    }()
    return output, nil
    
}

func (li *Line) String() string {
	return fmt.Sprintf(
		"%s\t%s\t%s\t%d\t%d\t%s\t%s\t%s",
		li.RemoteHost,
		li.Time,
		li.Request,
		li.Status,
		li.Bytes,
		li.Referer,
		li.UserAgent,
		li.URL,
	)
}

func CompileRegexp() (*regexp.Regexp, error) {
	var buffer bytes.Buffer
	buffer.WriteString(`^(\S+)\s`)                  // 1) IP
	buffer.WriteString(`\S+\s+`)                    // remote logname
	buffer.WriteString(`(?:\S+\s+)+`)               // remote user
	buffer.WriteString(`\[([^]]+)\]\s`)             // 2) date
	buffer.WriteString(`"(\S*)\s?`)                 // 3) method
	buffer.WriteString(`(?:((?:[^"]*(?:\\")?)*)\s`) // 4) URL
	buffer.WriteString(`([^"]*)"\s|`)               // 5) protocol
	buffer.WriteString(`((?:[^"]*(?:\\")?)*)"\s)`)  // 6) or, possibly URL with no protocol
	buffer.WriteString(`(\S+)\s`)                   // 7) status code
	buffer.WriteString(`(\S+)\s`)                   // 8) bytes
	buffer.WriteString(`"((?:[^"]*(?:\\")?)*)"\s`)  // 9) referrer
	buffer.WriteString(`"(.*)"$`)                   // 10) user agent
	return regexp.Compile(buffer.String())
}

func (p *Parser) ParseLine(line string) (*Line, error) {
	result := p.LineRegexp.FindStringSubmatch(line)

	lineItem := new(Line)
    if len(result) < 9 {
        return nil, errors.New("Unable to parse line")
    }
	lineItem.RemoteHost = result[1]
	// [05/Oct/2014:04:06:21 -0500]
	value := result[2]
	t, _ := time.Parse(p.Layout, value)
	lineItem.Time = t
	lineItem.Request = result[3] + " " + result[4] + " " + result[5]
	status, err := strconv.Atoi(result[7])
	if err != nil {
		status = 0
	}
	bytes, err := strconv.Atoi(result[8])
	if err != nil {
		bytes = 0
	}
	lineItem.Status = status
	lineItem.Bytes = bytes
	lineItem.Referer = result[9]
	lineItem.UserAgent = result[10]
	url := result[4]
	altURL := result[6]
	if url == "" && altURL != "" {
		url = altURL
	}
	lineItem.URL = url
	return lineItem, nil
}
