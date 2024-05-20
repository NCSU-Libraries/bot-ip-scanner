# Cloud/Bot Request Analyzer

Sample golang program to analyze Apache logs (Combined format) to detect
requests identified as coming from questionable ranges that have violated
`robots.txt` and other reasonable measures to prevent abuse.

## Building

    $ go build .

This creates `./logparse`, a Linux ELF binary that can be installed on any RHEL server.

## Usage

    $ ./logparse server-id-secure_access_ssl.log > concatenated-json-bannable-requests.json

As indicated, the output is "concatenated JSON" that can be parsed by tools 
such as `yajl` and `jq` (not quite ndjson and definitely not valid spec-compliant JSON); each record has the keys `ipv4`, `source`, `range`,
`query_string`, and `time` indicating the source IP, name assigned to the
owner, the CIDR range detected as containing the IP, the query string, and the
time of the request.

## Caveats

The source list has not been extensively vetted, nor has the code. This tool
does not ban any IP addresses on its own, it is intended as a tool for analysis
to detect the scale of the problem.

## Ideas for Future Development

. Add switches to select output format
. Add arguments to allow selecting requests that fall in a certain time range

## Thanks 

Source IP list pulled from
https://raw.githubusercontent.com/pulibrary/princeton_ansible/main/roles/denyhost/vars/main.yml (stored here as `internal/util/princeton_ban_list.yml`)
so thanks to the folks at Princeton University Libraries for the basic idea.

