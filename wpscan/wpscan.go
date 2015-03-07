package wpscan

import (
	"code.google.com/p/go.net/context"
	"github.com/facebookgo/stackerr"

	"fmt"
	"github.com/bearded-web/bearded/models/plan"
	"github.com/bearded-web/bearded/models/report"
	"github.com/bearded-web/bearded/pkg/script"
)

const (
	toolName = "barbudo/wpscan"

	homeDir       = "/home/app"
)

type Wpscan struct {
}

func NewWpscan() *Wpscan {
	return &Wpscan{}
}

func (s *Wpscan) Handle(ctx context.Context, client script.ClientV1, conf *plan.Conf) error {
	// Check if plugin is available
	println("get tool")
	pl, err := s.getTool(ctx, client)
	if err != nil {
		return err
	}
	println("run wpscan")
	// Run wpscan util
	rep, err := pl.Run(ctx, pl.LatestVersion(), &plan.Conf{
		CommandArgs: fmt.Sprintf("--url %s --follow-redirection --batch --no-color", conf.Target),
	})
	if err != nil {
		return stackerr.Wrap(err)
	}
	println("wpscan finished")
	// Get and parse w3af output
	if rep.Type != report.TypeRaw {
		return stackerr.Newf("Wpscan report type should be TypeRaw, but got %s instead", rep.Type)
	}
	resultReport := report.Report{Type: report.TypeEmpty}
	println("transofrm report")
	issues, err := parseReport(rep.Raw.Raw)
	if err != nil {
		return stackerr.Wrap(err)
	}
	if len(issues) > 0 {
		resultReport.Type = report.TypeIssues
		resultReport.Issues = issues
	}
	// push reports
	client.SendReport(ctx, &resultReport)
	//	spew.Dump(resultReport)
	println("sent")
	// exit
	return nil
}

// Check if w3af plugin is available
func (s *Wpscan) getTool(ctx context.Context, client script.ClientV1) (*script.Plugin, error) {
	pl, err := client.GetPlugin(ctx, toolName)
	if err != nil {
		return nil, err
	}
	return pl, err
}