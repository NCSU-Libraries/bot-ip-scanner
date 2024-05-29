package util

import (
    "fmt"
    "github.com/mileusna/useragent"
    "log"
    "strconv"
    "strings"
    "time"
)

type ChromeVersion struct {
    MajorVersion int
    ReleaseDate time.Time
}

// https://chromestatus.com/roadmap
var pivotChromeVersion = &ChromeVersion{125, time.Date(2024, 5, 8, 0, 0, 0, 0, time.Local)}


// heuristic -- releases every four weeks
// https://chromium.googlesource.com/chromium/src/+/master/docs/process/release_cycle.md
func ChromeReleaseDate(majorVersion int) (time.Time) {
    vdelt := pivotChromeVersion.MajorVersion - majorVersion
    sDelt := vdelt * 28 * 24 * 3600 * 1000 * 1000 * 1000
    log.Printf("Seconds since %d was released: %d\n", majorVersion, sDelt) 
    return pivotChromeVersion.ReleaseDate.Add(time.Duration(-sDelt))
}

func majorVersion(version string) (int, error) {
    var integerPart string
    if dotIdx := strings.Index(version, "."); dotIdx > -1 {
        integerPart = version[:dotIdx]
    } else {
        integerPart = version
    }
    log.Printf("Integer part: %s\n", integerPart)
    return strconv.Atoi(integerPart)
}
    

func LooksSuspicious(ua useragent.UserAgent) bool {
    if ua.IsChrome() {
        mv, err := majorVersion(ua.Version)
        if err == nil {
            log.Printf("I project that %s was released on %s\n", ua.String, ChromeReleaseDate(mv))
        } 
        
    }
    return true
}
        
func SummarizeUserAgent(ua_verbatim string) string {
    ua := useragent.Parse(ua_verbatim)
    if LooksSuspicious(ua) {
        log.Println("%s looks suspicious", ua)
    }
    return fmt.Sprintf("%s %s on %s %s", ua.Name, ua.Version, ua.OS, ua.OSVersion)
}




//    here are some user agents -- summarized by a not-terribly nuanced parser into "[name] [version] on [os] [os version]" format -- found to be emanating from Tencent data center
