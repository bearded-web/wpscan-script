package wpscan

import (
	"encoding/json"
	"io/ioutil"
	"path"
	"testing"

	"github.com/bearded-web/bearded/models/report"
	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseLine(t *testing.T) {
	data := []struct {
		Val      string
		Expected *Line
	}{
		{"[i] data", &Line{LInfo, "data"}},
		{"[+] metadata", &Line{LMeta, "metadata"}},
		{"[!]    warndata", &Line{LWarn, "warndata"}},
		{"    empty data", &Line{LEmpty, "empty data"}},
	}
	for _, d := range data {
		assert.Equal(t, d.Expected, parseLine(d.Val))
	}
}

func TestParseReport(t *testing.T) {
	data := loadTestData("raw_report_1.txt")
	issues, err := parseReport(string(data))
	require.NoError(t, err)
	spew.Dump(issues)
	assert.Len(t, issues, 5)
}

// test data
const testDataDir = "../test_data"

func loadTestData(filename string) []byte {
	file := path.Join(testDataDir, filename)
	raw, err := ioutil.ReadFile(file)
	if err != nil {
		panic(err)
	}
	return raw
}

func loadReport(filename string) *report.Report {
	rep := report.Report{}
	if err := json.Unmarshal(loadTestData(filename), &rep); err != nil {
		panic(err)
	}
	return &rep
}
