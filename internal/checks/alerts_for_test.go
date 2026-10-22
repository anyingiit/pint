package checks_test

import (
	"context"
	"testing"

	"github.com/cloudflare/pint/internal/checks"
	"github.com/cloudflare/pint/internal/promapi"
)

func newAlertsForCheck(_ *promapi.FailoverGroup) checks.RuleChecker {
	return checks.NewAlertsForCheck()
}

func alertsForSettings(t *testing.T, redundant bool) func(context.Context, string) context.Context {
	return func(ctx context.Context, _ string) context.Context {
		s := checks.AlertsForSettings{
			Redundant: &redundant,
		}
		if err := s.Validate(); err != nil {
			t.Error(err)
			t.FailNow()
		}
		return context.WithValue(ctx, checks.SettingsKey(checks.AlertForCheckName), &s)
	}
}

func TestAlertsForCheck(t *testing.T) {
	testCases := []checkTest{
		{
			description: "ignores rules with syntax errors",
			content:     "- alert: foo\n  expr: sum(foo) without(\n",
			checker:     newAlertsForCheck,
			prometheus:  noProm,
		},
		{
			description: "ignores recording rules",
			content:     "- record: foo\n  expr: sum(foo) without(job)\n",
			checker:     newAlertsForCheck,
			prometheus:  noProm,
		},
		{
			description: "invalid for value",
			content:     "- alert: foo\n  expr: foo\n  for: abc\n",
			checker:     newAlertsForCheck,
			prometheus:  noProm,
			problems:    true,
		},
		{
			description: "negative for value",
			content:     "- alert: foo\n  expr: foo\n  for: -5m\n",
			checker:     newAlertsForCheck,
			prometheus:  noProm,
			problems:    true,
		},
		{
			description: "default for value",
			content:     "- alert: foo\n  expr: foo\n  for: 0h\n",
			checker:     newAlertsForCheck,
			prometheus:  noProm,
			problems:    true,
		},
		{
			description: "invalid keep_firing_for value",
			content:     "- alert: foo\n  expr: foo\n  keep_firing_for: abc\n",
			checker:     newAlertsForCheck,
			prometheus:  noProm,
			problems:    true,
		},
		{
			description: "negative keep_firing_for value",
			content:     "- alert: foo\n  expr: foo\n  keep_firing_for: -5m\n",
			checker:     newAlertsForCheck,
			prometheus:  noProm,
			problems:    true,
		},
		{
			description: "default for value",
			content:     "- alert: foo\n  expr: foo\n  keep_firing_for: 0h\n",
			checker:     newAlertsForCheck,
			prometheus:  noProm,
			problems:    true,
		},
		{
			description: "valid for value",
			content:     "- alert: foo\n  expr: foo\n  for: 5m\n",
			checker:     newAlertsForCheck,
			prometheus:  noProm,
		},
		{
			description: "valid keep_firing_for value",
			content:     "- alert: foo\n  expr: foo\n  keep_firing_for: 10m\n",
			checker:     newAlertsForCheck,
			prometheus:  noProm,
		},
		{
			description: "default for value / redundant enabled",
			content:     "- alert: foo\n  expr: foo\n  for: 0m\n",
			checker:     newAlertsForCheck,
			ctx:         alertsForSettings(t, true),
			prometheus:  noProm,
			problems:    true,
		},
		{
			description: "default for value / redundant disabled",
			content:     "- alert: foo\n  expr: foo\n  for: 0m\n",
			checker:     newAlertsForCheck,
			ctx:         alertsForSettings(t, false),
			prometheus:  noProm,
		},
		{
			description: "default keep_firing_for value / redundant disabled",
			content:     "- alert: foo\n  expr: foo\n  keep_firing_for: 0s\n",
			checker:     newAlertsForCheck,
			ctx:         alertsForSettings(t, false),
			prometheus:  noProm,
		},
		{
			description: "invalid for value / redundant disabled",
			content:     "- alert: foo\n  expr: foo\n  for: -5m\n",
			checker:     newAlertsForCheck,
			ctx:         alertsForSettings(t, false),
			prometheus:  noProm,
			problems:    true,
		},
	}
	runTests(t, testCases)
}
