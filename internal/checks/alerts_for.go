package checks

import (
	"context"
	"fmt"

	"github.com/cloudflare/pint/internal/diags"
	"github.com/cloudflare/pint/internal/discovery"
	"github.com/cloudflare/pint/internal/parser"
)

const (
	AlertForCheckName         = "alerts/for"
	AlertForCheckDurationHelp = `Supported time durations are documented [here](https://prometheus.io/docs/prometheus/latest/querying/basics/#time-durations).`
)

func NewAlertsForCheck() AlertsForChecksFor {
	return AlertsForChecksFor{}
}

type AlertsForSettings struct {
	Redundant        *bool `hcl:"redundant,optional" json:"redundant,omitzero"`
	redundantEnabled bool
}

func (c *AlertsForSettings) Validate() error {
	c.redundantEnabled = true
	if c.Redundant != nil {
		c.redundantEnabled = *c.Redundant
	}
	return nil
}

type AlertsForChecksFor struct{}

func (c AlertsForChecksFor) Meta() CheckMeta {
	return CheckMeta{
		States: []discovery.ChangeType{
			discovery.Noop,
			discovery.Added,
			discovery.Modified,
			discovery.Moved,
		},
		Online:        false,
		AlwaysEnabled: false,
	}
}

func (c AlertsForChecksFor) String() string {
	return AlertForCheckName
}

func (c AlertsForChecksFor) Reporter() string {
	return AlertForCheckName
}

func (c AlertsForChecksFor) Check(ctx context.Context, entry *discovery.Entry, _ []*discovery.Entry) (problems []Problem) {
	if entry.Rule.AlertingRule == nil {
		return problems
	}

	var settings *AlertsForSettings
	if s := ctx.Value(SettingsKey(c.Reporter())); s != nil {
		settings = s.(*AlertsForSettings)
	}
	if settings == nil {
		settings = &AlertsForSettings{}
		_ = settings.Validate()
	}

	if entry.Rule.AlertingRule.For != nil {
		problems = append(problems, c.checkField(settings, "for", entry.Rule.AlertingRule.For)...)
	}
	if entry.Rule.AlertingRule.KeepFiringFor != nil {
		problems = append(problems, c.checkField(settings, "keep_firing_for", entry.Rule.AlertingRule.KeepFiringFor)...)
	}

	return problems
}

func (c AlertsForChecksFor) checkField(settings *AlertsForSettings, name string, value *parser.YamlDuration) (problems []Problem) {
	if value.ParseError != nil {
		problems = append(problems, Problem{
			Anchor:   AnchorAfter,
			Lines:    value.Pos.Lines(),
			Reporter: c.Reporter(),
			Summary:  "invalid duration",
			Details:  AlertForCheckDurationHelp,
			Severity: Bug,
			Diagnostics: []diags.Diagnostic{
				{
					Message:     value.ParseError.Error(),
					Pos:         value.Pos,
					Expr:        nil,
					FirstColumn: 1,
					LastColumn:  value.Pos.Len(),
					Kind:        diags.Issue,
				},
			},
		})
		return problems
	}

	if settings.redundantEnabled && value.Value == 0 {
		problems = append(problems, Problem{
			Anchor:   AnchorAfter,
			Lines:    value.Pos.Lines(),
			Reporter: c.Reporter(),
			Summary:  "redundant field with default value",
			Details:  "",
			Severity: Information,
			Diagnostics: []diags.Diagnostic{
				{
					Message:     fmt.Sprintf("`%s` is the default value of `%s`, this line is unnecessary.", value.Raw, name),
					Pos:         value.Pos,
					Expr:        nil,
					FirstColumn: 1,
					LastColumn:  value.Pos.Len(),
					Kind:        diags.Issue,
				},
			},
		})
	}

	return problems
}
