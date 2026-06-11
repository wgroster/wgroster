// Command wgroster is a self-service WireGuard configuration portal with an
// LDAP login, admin-managed endpoints and a live status dashboard.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/wgroster/wgroster/internal/config"
	"github.com/wgroster/wgroster/internal/geoip"
	"github.com/wgroster/wgroster/internal/ipam"
	"github.com/wgroster/wgroster/internal/ldap"
	"github.com/wgroster/wgroster/internal/store"
	"github.com/wgroster/wgroster/internal/web"
	"golang.org/x/crypto/bcrypt"
)

// version is the build version, injected at release time via -ldflags
// "-X main.version=...". It stays "dev" for local and untagged builds.
var version = "dev"

func main() {
	configPath := flag.String("config", "config.yaml", "path to the YAML configuration file")
	hashPassword := flag.Bool("hash-password", false, "read a password from stdin and print its bcrypt hash, then exit")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return
	}

	if *hashPassword {
		hashPasswordFromStdin()
		return
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	pool, err := ipam.New(cfg.VPNCIDR)
	if err != nil {
		log.Fatalf("ipam: %v", err)
	}

	st, err := store.Open(cfg.Database)
	if err != nil {
		log.Fatalf("store: %v", err)
	}
	defer st.Close()

	geo, err := geoip.New(cfg.GeoIPCityDB, cfg.GeoIPASNDB)
	if err != nil {
		log.Fatalf("geoip: %v", err)
	}
	defer geo.Close()

	srv, err := web.New(cfg, st, ldap.New(cfg.LDAP), pool, geo)
	if err != nil {
		log.Fatalf("web: %v", err)
	}

	httpSrv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	// Run the server until a termination signal arrives, then shut down cleanly
	// so in-flight requests finish and the SQLite database is closed properly.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Background health-alert evaluation (no-op unless a webhook is configured).
	go srv.RunAlerts(ctx)
	// Expire stale pending machines (no-op unless pending_expiry_days is set).
	go srv.RunMaintenance(ctx)
	// Purge expired server-side sessions hourly.
	go srv.RunSessionGC(ctx)

	go func() {
		log.Printf("wgroster %s listening on %s (vpn pool %s)", version, cfg.Listen, pool.CIDR())
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("listen: %v", err)
		}
	}()

	<-ctx.Done()
	log.Print("shutting down…")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpSrv.Shutdown(shutdownCtx); err != nil {
		log.Printf("graceful shutdown failed: %v", err)
	}
}

// hashPasswordFromStdin reads a single line from stdin and prints its bcrypt
// hash, suitable for local_admin.password_hash in the configuration.
func hashPasswordFromStdin() {
	fmt.Fprint(os.Stderr, "Password: ")
	scanner := bufio.NewScanner(os.Stdin)
	if !scanner.Scan() {
		log.Fatal("no password provided")
	}
	password := strings.TrimRight(scanner.Text(), "\r\n")
	if password == "" {
		log.Fatal("empty password")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Fatalf("hash: %v", err)
	}
	fmt.Println(string(hash))
}
