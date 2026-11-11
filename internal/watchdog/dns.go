package watchdog

import (
	"context"
	"time"

	"github.com/repentandliveholy/netriser/internal/netengine"
)

// DNS-only failures have their own recovery path and never enter the network
// escalation ladder, including when reboot is enabled or recovery is disabled.
func (w *Watchdog) recoverDNS(ctx context.Context, report *CheckReport) (*CheckReport, error) {
	report.RemediationStage = 0
	report.StageReason = "System DNS failed while IP connectivity is healthy; DNS-only recovery, no reboot escalation"
	if !w.cfg.ObservationMode {
		if err := w.writeFailCount(0); err != nil {
			return report, err
		}
		report.FailCount = 0
	}
	w.logger.Warn("DNS resolution FAILED while IP connectivity is healthy")
	engine, supported := w.engine.(netengine.DNSRecoveryEngine)
	if w.cfg.ObservationMode || !w.cfg.AllowDNSRecovery || !supported {
		report.ActionsTaken = append(report.ActionsTaken, netengine.ActionResult{Type: netengine.ActionRestoreDNS, Target: "system resolver", Status: netengine.ActionSkipped, Description: "DNS recovery disabled, observation mode, or unsupported platform; reboot escalation suppressed"})
		return report, nil
	}
	actions, err := engine.RestoreDNS(ctx)
	report.ActionsTaken = append(report.ActionsTaken, actions...)
	for _, action := range actions {
		w.logger.Recovery("  - %s", action.String())
	}
	if err != nil {
		w.logger.Warn("DNS recovery failed: %v", err)
	}
	// Allow the pure Go resolver's cached resolv.conf to expire before verifying.
	if err := w.clock.Sleep(ctx, 5*time.Second); err != nil {
		return report, err
	}
	post := w.checker.CheckFast(ctx)
	report.Healthy = post.Healthy
	report.PostCanaryResult = &post
	report.Remediated = post.Healthy
	if post.Healthy {
		w.logger.Info("System DNS RESTORED without reboot")
	}
	return report, nil
}
