package wpscan

import (
	"strings"
	"github.com/bearded-web/bearded/models/issue"
)

const (
	BlockMeta = iota
	BlockWpVulns
	BlockPluginVulns
)

const (
	LEmpty = ""
	LInfo  = "[i]"
	LMeta  = "[+]"
	LWarn  = "[!]"
)

var LTypes = []string{LInfo, LMeta, LWarn}

type Line struct {
	Type string
	Data string
}

const (
	RobotsAvail = "robots.txt available under:"
	RobotsEntry = "Interesting entry from robots.txt:"
)

//type Lines struct {
//	Data []string
//	i int
//}
//
//func ParseLines(raw string) Lines {
//	return Lines{Data: strings.Split(raw, "\n"), i: 0}
//}

func parseLine(rawLine string) *Line {
	l := Line{}
	for _, lType := range LTypes {
		if strings.HasPrefix(rawLine, lType) {
			l.Type = lType
			break
		}
	}
	data := strings.TrimPrefix(rawLine, l.Type)
	data = strings.TrimSpace(data)
	l.Data = data
	return &l
}

func parseReport(raw string) ([]*issue.Issue, error) {
	issues := []*issue.Issue{}

	block := BlockMeta
	lines := strings.Split(raw, "\n")
	robotsIssue := &issue.Issue{
		Severity: issue.SeverityInfo,
	}
	robotEntries := []string{}
	barrier := len(lines) - 1
loop:
	for i := 0; i < barrier; i++ {
		line := parseLine(lines[i])
		if line.Type == LWarn && strings.Contains(line.Data, "vulnerabilities identified from the version number") {
			block = BlockWpVulns
			continue loop
		}
		if line.Type == LMeta && strings.Contains(line.Data, "Enumerating plugins") {
			block = BlockPluginVulns
			continue loop
		}
		switch block {
		case BlockMeta:
			// robots
			if line.Type == LMeta && strings.Contains(line.Data, RobotsAvail) {
				// TODO: do job with regular expressions
				robotsIssue.Summary = "Found robots.txt with interesting entries"
				u := strings.TrimPrefix(line.Data, RobotsAvail)
				u = strings.TrimSpace(strings.Trim(u, "'"))
				robotsIssue.Vector = &issue.Vector{Url: u}
				continue loop
			}
			if line.Type == LMeta && strings.Contains(line.Data, RobotsEntry) {
				entry := strings.TrimSpace(strings.TrimPrefix(line.Data, RobotsEntry))
				robotEntries = append(robotEntries, entry)
				continue loop
			}
		case BlockWpVulns:
			if line.Type == LWarn && strings.Contains(line.Data, "Title:") {
				summary := strings.TrimSpace(strings.TrimPrefix(line.Data, "Title:"))
				issueObj := &issue.Issue{
					Severity: issue.SeverityMedium,
					Summary:  summary,
				}
				for {
					i += 1
					if i+1 >= barrier {
						break
					}
					line := parseLine(lines[i])
					if line.Data == "" {
						break
					}
					if line.Type == LInfo && strings.Contains(line.Data, "Fixed in:") {
						issueObj.Desc += line.Data
						break
					}
					if line.Type == LEmpty && strings.Contains(line.Data, "Reference: ") {
						u := strings.TrimPrefix(line.Data, "Reference: ")
						u = strings.TrimSpace(u)
						issueObj.References = append(issueObj.References, &issue.Reference{Url: u})
						continue
					}
				}
				issues = append(issues, issueObj)
			}
		}
	}
	if len(robotEntries) > 0 {
		robotsIssue.Desc = strings.Join(robotEntries, "\n")
		issues = append(issues, robotsIssue)
	}

	return issues, nil
}
