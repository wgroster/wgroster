package web

import (
	"context"
	"log"
	"time"
)

// RunMaintenance periodically expires stale pending machines (freeing their
// reserved IP) and prunes the audit log. No-op unless pending_expiry_days or
// audit_retention_days is configured. Cancel ctx to stop.
func (s *Server) RunMaintenance(ctx context.Context) {
	if s.cfg.PendingExpiryDays <= 0 && s.cfg.AuditRetentionDays <= 0 {
		return
	}
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		s.sweep()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// sweep runs one round of retention: expired pending machines, then old audit
// entries. Each step is independent and skipped when not configured.
func (s *Server) sweep() {
	if days := s.cfg.PendingExpiryDays; days > 0 {
		cutoff := time.Now().Add(-time.Duration(days) * 24 * time.Hour)
		if n, err := s.store.DeleteExpiredPending(cutoff); err != nil {
			log.Printf("pending expiry: %v", err)
		} else if n > 0 {
			log.Printf("pending expiry: removed %d expired pending machine(s)", n)
		}
	}
	if days := s.cfg.AuditRetentionDays; days > 0 {
		cutoff := time.Now().Add(-time.Duration(days) * 24 * time.Hour)
		if n, err := s.store.DeleteAuditBefore(cutoff); err != nil {
			log.Printf("audit retention: %v", err)
		} else if n > 0 {
			log.Printf("audit retention: removed %d audit entr(ies)", n)
		}
	}
}

// RunSessionGC periodically purges expired server-side sessions so the table
// does not grow without bound from users who never explicitly log out. Cancel
// ctx to stop.
func (s *Server) RunSessionGC(ctx context.Context) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		if n, err := s.sess.SweepExpired(); err != nil {
			log.Printf("session gc: %v", err)
		} else if n > 0 {
			log.Printf("session gc: removed %d expired session(s)", n)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
