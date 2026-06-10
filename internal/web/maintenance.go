package web

import (
	"context"
	"log"
	"time"
)

// RunMaintenance periodically expires stale pending machines (freeing their
// reserved IP). No-op unless pending_expiry_days is configured. Cancel ctx to
// stop.
func (s *Server) RunMaintenance(ctx context.Context) {
	if s.cfg.PendingExpiryDays <= 0 {
		return
	}
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		cutoff := time.Now().Add(-time.Duration(s.cfg.PendingExpiryDays) * 24 * time.Hour)
		if n, err := s.store.DeleteExpiredPending(cutoff); err != nil {
			log.Printf("pending expiry: %v", err)
		} else if n > 0 {
			log.Printf("pending expiry: removed %d expired pending machine(s)", n)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
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
