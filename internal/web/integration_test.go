package web

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/wgroster/wgroster/internal/config"
	"github.com/wgroster/wgroster/internal/ipam"
	"github.com/wgroster/wgroster/internal/ldap"
	"github.com/wgroster/wgroster/internal/store"
	"golang.org/x/crypto/bcrypt"
)

func key(b byte) string {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = b
	}
	return base64.StdEncoding.EncodeToString(raw)
}

// testServer builds a Server backed by a temp SQLite DB and an admin session.
func testServer(t *testing.T) (*Server, http.Handler, []*http.Cookie, string) {
	t.Helper()
	st, err := store.Open(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	cfg := &config.Config{SessionKey: "0123456789abcdef0123456789abcdef", VPNCIDR: "10.0.0.0/16", BaseURL: "http://x"}
	pool, _ := ipam.New(cfg.VPNCIDR)
	srv, err := New(cfg, st, ldap.New(cfg.LDAP), pool, nil, "dev")
	if err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	sess, err := srv.sess.Issue(rec, "admin", "", true, true)
	if err != nil {
		t.Fatal(err)
	}
	return srv, srv.Handler(), rec.Result().Cookies(), sess.CSRF
}

func do(t *testing.T, h http.Handler, method, path string, cookies []*http.Cookie, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	var body *strings.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	} else {
		body = strings.NewReader("")
	}
	r := httptest.NewRequest(method, path, body)
	if form != nil {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for _, c := range cookies {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestEndToEndFlow(t *testing.T) {
	srv, h, cookies, csrf := testServer(t)
	epKey := key(2)
	mKey := key(1)

	// 1. Admin creates an endpoint.
	w := do(t, h, "POST", "/admin/endpoints", cookies, url.Values{
		"csrf": {csrf}, "name": {"paris"}, "public_key": {epKey},
		"host_port": {"vpn-par:51820"}, "allowed_ips": {"192.168.1.0/24"},
		"persistent_keepalive": {"25"},
	})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("create endpoint: got %d (%s)", w.Code, w.Body)
	}
	eps, _ := srv.store.ListEndpoints()
	if len(eps) != 1 {
		t.Fatalf("expected 1 endpoint, got %d", len(eps))
	}
	ep := eps[0]

	// 2. User adds a machine.
	w = do(t, h, "POST", "/machines", cookies, url.Values{
		"csrf": {csrf}, "name": {"laptop"}, "public_key": {mKey},
	})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("add machine: got %d", w.Code)
	}
	machines, _ := srv.store.ListMachines()
	if len(machines) != 1 || machines[0].Status != store.StatusPending {
		t.Fatalf("expected 1 pending machine, got %+v", machines)
	}
	mID := machines[0].ID

	// 3. Admin approves it (edit modal: name, public key, address, endpoint).
	w = do(t, h, "POST", fmt.Sprintf("/admin/machines/%d", mID), cookies, url.Values{
		"csrf": {csrf}, "name": {"laptop"}, "public_key": {mKey},
		"address": {"10.0.0.5"}, "endpoint_ids": {fmt.Sprint(ep.ID)},
	})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("approve: got %d (%s)", w.Code, w.Body)
	}

	// 4. User downloads the config.
	w = do(t, h, "GET", fmt.Sprintf("/machines/%d/config?download=1", mID), cookies, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("config download: got %d", w.Code)
	}
	for _, want := range []string{"Address = 10.0.0.5/32", "Endpoint = vpn-par:51820", "AllowedIPs = 192.168.1.0/24"} {
		if !strings.Contains(w.Body.String(), want) {
			t.Errorf("config missing %q", want)
		}
	}

	// 5. An out-of-range address is rejected.
	w = do(t, h, "POST", fmt.Sprintf("/admin/machines/%d", mID), cookies, url.Values{
		"csrf": {csrf}, "name": {"laptop"}, "public_key": {mKey},
		"address": {"192.0.2.1"}, "endpoint_ids": {fmt.Sprint(ep.ID)},
	})
	if w.Code != http.StatusSeeOther || !strings.Contains(w.Header().Get("Location"), "err=") {
		t.Errorf("expected out-of-range address rejection, got %d %q", w.Code, w.Header().Get("Location"))
	}

	// 6. Concentrator uploads a status dump (bearer token).
	dump := fmt.Sprintf("%s\t(none)\t203.0.113.5:1234\t10.0.0.5/32\t%d\t1024\t2048\t25", mKey, time.Now().Unix())
	r := httptest.NewRequest("POST", fmt.Sprintf("/api/endpoints/%d/status", ep.ID), strings.NewReader(dump))
	r.Header.Set("Authorization", "Bearer "+ep.UploadToken)
	sw := httptest.NewRecorder()
	h.ServeHTTP(sw, r)
	if sw.Code != http.StatusNoContent {
		t.Fatalf("status upload: got %d (%s)", sw.Code, sw.Body)
	}

	// 7. Status table shows the peer as online.
	w = do(t, h, "GET", "/admin/status/table", cookies, nil)
	if !strings.Contains(w.Body.String(), "online") || !strings.Contains(w.Body.String(), "laptop") {
		t.Errorf("status table missing online laptop:\n%s", w.Body)
	}

	// 8. Expected-peers (wg format) lists the machine for provisioning.
	r = httptest.NewRequest("GET", fmt.Sprintf("/api/endpoints/%d/expected-peers?format=wg", ep.ID), nil)
	r.Header.Set("Authorization", "Bearer "+ep.UploadToken)
	pw := httptest.NewRecorder()
	h.ServeHTTP(pw, r)
	if !strings.Contains(pw.Body.String(), mKey) || !strings.Contains(pw.Body.String(), "AllowedIPs = 10.0.0.5/32") {
		t.Errorf("expected-peers missing entry:\n%s", pw.Body)
	}

	// 8b. The concentrator can pull its own full wg0.conf with the same token.
	r = httptest.NewRequest("GET", fmt.Sprintf("/api/endpoints/%d/config", ep.ID), nil)
	r.Header.Set("Authorization", "Bearer "+ep.UploadToken)
	cw := httptest.NewRecorder()
	h.ServeHTTP(cw, r)
	for _, want := range []string{"[Interface]", "<CONCENTRATOR_PRIVATE_KEY>", "[Peer]", mKey, "AllowedIPs = 10.0.0.5/32"} {
		if !strings.Contains(cw.Body.String(), want) {
			t.Errorf("endpoint config missing %q:\n%s", want, cw.Body)
		}
	}

	// 9. A wrong token is rejected. The response is 404 (identical to an unknown
	// endpoint id) so endpoint ids cannot be enumerated by status code.
	r = httptest.NewRequest("GET", fmt.Sprintf("/api/endpoints/%d/expected-peers", ep.ID), nil)
	r.Header.Set("Authorization", "Bearer wrong")
	bw := httptest.NewRecorder()
	h.ServeHTTP(bw, r)
	if bw.Code != http.StatusNotFound {
		t.Errorf("bad token: got %d, want 404", bw.Code)
	}
}

func TestLocalAdminLogin(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("s3cret"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		la   config.LocalAdmin
		pass string
		ok   bool
	}{
		{"bcrypt ok", config.LocalAdmin{Username: "admin", PasswordHash: string(hash)}, "s3cret", true},
		{"bcrypt wrong", config.LocalAdmin{Username: "admin", PasswordHash: string(hash)}, "nope", false},
		{"plain ok", config.LocalAdmin{Username: "admin", Password: "p4ss"}, "p4ss", true},
		{"plain wrong", config.LocalAdmin{Username: "admin", Password: "p4ss"}, "x", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			st, _ := store.Open(t.TempDir() + "/test.db")
			defer st.Close()
			cfg := &config.Config{SessionKey: "0123456789abcdef0123456789abcdef", VPNCIDR: "10.0.0.0/16", LocalAdmin: c.la}
			pool, _ := ipam.New(cfg.VPNCIDR)
			srv, err := New(cfg, st, ldap.New(cfg.LDAP), pool, nil, "dev")
			if err != nil {
				t.Fatal(err)
			}
			h := srv.Handler()

			w := do(t, h, "POST", "/login", nil, url.Values{"uid": {"admin"}, "password": {c.pass}})
			loc := w.Header().Get("Location")
			gotSession := len(w.Result().Cookies()) > 0

			if c.ok {
				if loc != "/" || !gotSession {
					t.Fatalf("expected successful login, got location=%q session=%v", loc, gotSession)
				}
				// The minted session must grant admin access.
				w2 := do(t, h, "GET", "/admin/endpoints", w.Result().Cookies(), nil)
				if w2.Code != http.StatusOK {
					t.Errorf("admin page: got %d, want 200", w2.Code)
				}
			} else {
				if !strings.Contains(loc, "err=") || gotSession {
					t.Fatalf("expected rejected login, got location=%q session=%v", loc, gotSession)
				}
			}
		})
	}
}

func TestRegenerateToken(t *testing.T) {
	srv, h, cookies, csrf := testServer(t)
	w := do(t, h, "POST", "/admin/endpoints", cookies, url.Values{
		"csrf": {csrf}, "name": {"paris"}, "public_key": {key(2)}, "host_port": {"vpn:51820"},
	})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("create endpoint: %d", w.Code)
	}
	eps, _ := srv.store.ListEndpoints()
	ep := eps[0]
	old := ep.UploadToken

	w = do(t, h, "POST", fmt.Sprintf("/admin/endpoints/%d/regenerate-token", ep.ID), cookies, url.Values{"csrf": {csrf}})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("regenerate: %d", w.Code)
	}
	eps, _ = srv.store.ListEndpoints()
	if eps[0].UploadToken == old || eps[0].UploadToken == "" {
		t.Fatalf("token was not regenerated (%q -> %q)", old, eps[0].UploadToken)
	}

	// The old token must no longer authenticate (404: indistinguishable from an
	// unknown endpoint id, to prevent enumeration).
	r := httptest.NewRequest("GET", fmt.Sprintf("/api/endpoints/%d/expected-peers", ep.ID), nil)
	r.Header.Set("Authorization", "Bearer "+old)
	rw := httptest.NewRecorder()
	h.ServeHTTP(rw, r)
	if rw.Code != http.StatusNotFound {
		t.Errorf("old token still works: got %d, want 404", rw.Code)
	}
}

func TestMetricsAndSecurityHeaders(t *testing.T) {
	srv, h, cookies, csrf := testServer(t)
	do(t, h, "POST", "/admin/endpoints", cookies, url.Values{
		"csrf": {csrf}, "name": {"paris"}, "public_key": {key(2)}, "host_port": {"vpn:51820"},
	})

	// Security headers are present on a normal response, and the CSP is strict
	// (assets are self-hosted, so no unsafe-inline/unsafe-eval).
	w := do(t, h, "GET", "/login", nil, nil)
	csp := w.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Error("missing Content-Security-Policy header")
	}
	if strings.Contains(csp, "unsafe-inline") || strings.Contains(csp, "unsafe-eval") {
		t.Errorf("CSP is not strict: %q", csp)
	}

	// Embedded assets are served.
	for _, asset := range []string{"/static/app.css", "/static/app.js", "/static/htmx.min.js", "/static/qrcode.min.js"} {
		a := do(t, h, "GET", asset, nil, nil)
		if a.Code != http.StatusOK {
			t.Errorf("asset %s: got %d, want 200", asset, a.Code)
		}
	}
	// HSTS only when cookie_secure; testServer leaves it false.
	if w.Header().Get("Strict-Transport-Security") != "" {
		t.Error("unexpected HSTS header without cookie_secure")
	}

	// /metrics requires auth: anonymous is rejected, an admin session is allowed.
	if anon := do(t, h, "GET", "/metrics", nil, nil); anon.Code != http.StatusUnauthorized {
		t.Errorf("anonymous /metrics: got %d, want 401", anon.Code)
	}
	m := do(t, h, "GET", "/metrics", cookies, nil)
	if m.Code != http.StatusOK {
		t.Fatalf("/metrics with admin session: got %d", m.Code)
	}
	for _, want := range []string{"wg_endpoints_total 1", `wg_peers_online{endpoint="paris"}`, "wg_machines_total"} {
		if !strings.Contains(m.Body.String(), want) {
			t.Errorf("/metrics missing %q\n%s", want, m.Body)
		}
	}
	_ = srv
}

func TestMetricsTokenProtection(t *testing.T) {
	st, _ := store.Open(t.TempDir() + "/test.db")
	defer st.Close()
	cfg := &config.Config{SessionKey: "0123456789abcdef0123456789abcdef", VPNCIDR: "10.0.0.0/16", MetricsToken: "s3cret"}
	pool, _ := ipam.New(cfg.VPNCIDR)
	srv, err := New(cfg, st, ldap.New(cfg.LDAP), pool, nil, "dev")
	if err != nil {
		t.Fatal(err)
	}
	h := srv.Handler()

	r := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("no token: got %d, want 401", w.Code)
	}

	r = httptest.NewRequest("GET", "/metrics", nil)
	r.Header.Set("Authorization", "Bearer s3cret")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("with token: got %d, want 200", w.Code)
	}
}

func TestAdminCreateAndEditMachine(t *testing.T) {
	srv, h, cookies, csrf := testServer(t)
	do(t, h, "POST", "/admin/endpoints", cookies, url.Values{
		"csrf": {csrf}, "name": {"paris"}, "public_key": {key(2)}, "host_port": {"vpn:51820"},
	})
	ep := mustEndpoint(t, srv)

	// Admin creates a machine, active immediately (no pending step).
	w := do(t, h, "POST", "/admin/machines", cookies, url.Values{
		"csrf": {csrf}, "owner_uid": {"alice"}, "name": {"laptop"}, "public_key": {key(1)},
		"address": {"10.0.0.5"}, "endpoint_ids": {fmt.Sprint(ep.ID)},
	})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("create: got %d (%s)", w.Code, w.Body)
	}
	machines, _ := srv.store.ListMachines()
	if len(machines) != 1 {
		t.Fatalf("expected 1 machine, got %d", len(machines))
	}
	m := machines[0]
	if m.Status != store.StatusActive || m.Address != "10.0.0.5" || m.OwnerUID != "alice" {
		t.Fatalf("unexpected machine: %+v", m)
	}

	// Edit name and public key.
	w = do(t, h, "POST", fmt.Sprintf("/admin/machines/%d", m.ID), cookies, url.Values{
		"csrf": {csrf}, "name": {"laptop-pro"}, "public_key": {key(3)},
		"address": {"10.0.0.5"}, "endpoint_ids": {fmt.Sprint(ep.ID)},
	})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("edit: got %d (%s)", w.Code, w.Body)
	}
	got, _ := srv.store.GetMachine(m.ID)
	if got.Name != "laptop-pro" || got.PublicKey != key(3) {
		t.Errorf("edit not applied: name=%q key=%q", got.Name, got.PublicKey)
	}
}

func mustEndpoint(t *testing.T, srv *Server) *store.Endpoint {
	t.Helper()
	eps, err := srv.store.ListEndpoints()
	if err != nil || len(eps) == 0 {
		t.Fatalf("no endpoint: %v", err)
	}
	return eps[0]
}

func TestChangePassword(t *testing.T) {
	hash, _ := bcrypt.GenerateFromPassword([]byte("s3cret"), bcrypt.MinCost)
	st, _ := store.Open(t.TempDir() + "/test.db")
	defer st.Close()
	cfg := &config.Config{
		SessionKey: "0123456789abcdef0123456789abcdef", VPNCIDR: "10.0.0.0/16",
		LocalAdmin: config.LocalAdmin{Username: "admin", PasswordHash: string(hash)},
	}
	pool, _ := ipam.New(cfg.VPNCIDR)
	srv, err := New(cfg, st, ldap.New(cfg.LDAP), pool, nil, "dev")
	if err != nil {
		t.Fatal(err)
	}
	h := srv.Handler()

	rec := httptest.NewRecorder()
	sess, _ := srv.sess.Issue(rec, "admin", "", true, true)
	cookies := rec.Result().Cookies()

	// Wrong current password is rejected.
	w := do(t, h, "POST", "/account/password", cookies, url.Values{
		"csrf": {sess.CSRF}, "current_password": {"wrong"}, "new_password": {"newpassw0rd"}, "confirm_password": {"newpassw0rd"},
	})
	if !strings.Contains(w.Header().Get("Location"), "err=") {
		t.Errorf("expected rejection of wrong current password, got %q", w.Header().Get("Location"))
	}

	// Successful change.
	w = do(t, h, "POST", "/account/password", cookies, url.Values{
		"csrf": {sess.CSRF}, "current_password": {"s3cret"}, "new_password": {"newpassw0rd"}, "confirm_password": {"newpassw0rd"},
	})
	if !strings.Contains(w.Header().Get("Location"), "ok=") {
		t.Fatalf("change failed: %q", w.Header().Get("Location"))
	}

	// New password now logs in; the old one no longer works.
	if lw := do(t, h, "POST", "/login", nil, url.Values{"uid": {"admin"}, "password": {"newpassw0rd"}}); lw.Header().Get("Location") != "/" {
		t.Errorf("new password login failed: %q", lw.Header().Get("Location"))
	}
	if lw := do(t, h, "POST", "/login", nil, url.Values{"uid": {"admin"}, "password": {"s3cret"}}); !strings.Contains(lw.Header().Get("Location"), "err=") {
		t.Errorf("old password should be rejected, got %q", lw.Header().Get("Location"))
	}
}

func TestAlertsWebhook(t *testing.T) {
	ch := make(chan alertPayload, 4)
	ws := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var p alertPayload
		json.NewDecoder(r.Body).Decode(&p)
		ch <- p
	}))
	defer ws.Close()

	st, _ := store.Open(t.TempDir() + "/test.db")
	defer st.Close()
	cfg := &config.Config{SessionKey: "0123456789abcdef0123456789abcdef", VPNCIDR: "10.0.0.0/16", AlertWebhookURL: ws.URL}
	pool, _ := ipam.New(cfg.VPNCIDR)
	srv, err := New(cfg, st, ldap.New(cfg.LDAP), pool, nil, "dev")
	if err != nil {
		t.Fatal(err)
	}

	// Endpoint with an active machine but no report → "missing" drift.
	ep := &store.Endpoint{Name: "par", PublicKey: "k", HostPort: "h:1", UploadToken: "t"}
	st.CreateEndpoint(ep)
	m := &store.Machine{OwnerUID: "alice", Name: "laptop", PublicKey: "pk"}
	st.CreateMachine(m)
	if err := st.ApproveMachine(m.ID, "10.0.0.5", []int64{ep.ID}, "admin"); err != nil {
		t.Fatal(err)
	}

	firing := map[alertKey]string{}
	srv.evalAlerts(context.Background(), firing)

	select {
	case p := <-ch:
		if p.Type != "missing" || p.Status != "firing" || p.Endpoint != "par" {
			t.Errorf("unexpected alert payload: %+v", p)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no webhook call received")
	}

	// Second evaluation with the same state must not re-fire.
	srv.evalAlerts(context.Background(), firing)
	select {
	case p := <-ch:
		t.Errorf("unexpected re-fire: %+v", p)
	case <-time.After(300 * time.Millisecond):
	}
}

func TestUserEditOwnMachine(t *testing.T) {
	srv, h, _, _ := testServer(t)
	rec := httptest.NewRecorder()
	bob, _ := srv.sess.Issue(rec, "bob", "", false, false) // non-admin
	bobCookies := rec.Result().Cookies()

	bm := &store.Machine{OwnerUID: "bob", Name: "laptop", PublicKey: key(1)}
	srv.store.CreateMachine(bm)
	srv.store.ApproveMachine(bm.ID, "10.0.0.5", nil, "admin")
	am := &store.Machine{OwnerUID: "alice", Name: "alaptop", PublicKey: key(2)}
	srv.store.CreateMachine(am)
	srv.store.ApproveMachine(am.ID, "10.0.0.6", nil, "admin")

	// Rename only — stays active; address/endpoints in the form are ignored.
	w := do(t, h, "POST", fmt.Sprintf("/machines/%d", bm.ID), bobCookies, url.Values{
		"csrf": {bob.CSRF}, "name": {"laptop2"}, "public_key": {key(1)},
		"address": {"10.0.0.99"}, "endpoint_ids": {"999"},
	})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("rename: got %d", w.Code)
	}
	got, _ := srv.store.GetMachine(bm.ID)
	if got.Name != "laptop2" || got.Status != store.StatusActive || got.Address != "10.0.0.5" {
		t.Fatalf("after rename: %+v (address must stay 10.0.0.5, still active)", got)
	}

	// Change the public key — goes back to pending, address kept.
	w = do(t, h, "POST", fmt.Sprintf("/machines/%d", bm.ID), bobCookies, url.Values{
		"csrf": {bob.CSRF}, "name": {"laptop2"}, "public_key": {key(3)},
	})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("key change: got %d", w.Code)
	}
	got, _ = srv.store.GetMachine(bm.ID)
	if got.PublicKey != key(3) || got.Status != store.StatusPending || got.Address != "10.0.0.5" {
		t.Fatalf("after key change: %+v (want pending, key3, address kept)", got)
	}

	// Bob cannot edit Alice's machine.
	w = do(t, h, "POST", fmt.Sprintf("/machines/%d", am.ID), bobCookies, url.Values{
		"csrf": {bob.CSRF}, "name": {"hijack"}, "public_key": {key(4)},
	})
	if w.Code != http.StatusForbidden {
		t.Errorf("editing another user's machine: got %d, want 403", w.Code)
	}
}

func TestSelfEnroll(t *testing.T) {
	st, _ := store.Open(t.TempDir() + "/test.db")
	defer st.Close()
	cfg := &config.Config{
		SessionKey: "0123456789abcdef0123456789abcdef", VPNCIDR: "10.0.0.0/16",
		SelfEnroll: true, SelfEnrollEndpoint: "paris", MaxPendingPerUser: 1,
	}
	pool, _ := ipam.New(cfg.VPNCIDR)
	srv, err := New(cfg, st, ldap.New(cfg.LDAP), pool, nil, "dev")
	if err != nil {
		t.Fatal(err)
	}
	h := srv.Handler()
	ep := &store.Endpoint{Name: "paris", PublicKey: key(2), HostPort: "vpn:51820", AllowedIPs: "10.0.0.0/8", UploadToken: "t"}
	st.CreateEndpoint(ep)

	rec := httptest.NewRecorder()
	sess, _ := srv.sess.Issue(rec, "bob", "", false, false)
	cookies := rec.Result().Cookies()

	w := do(t, h, "POST", "/machines/enroll", cookies, url.Values{
		"csrf": {sess.CSRF}, "name": {"phone"}, "public_key": {key(1)},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("enroll: got %d (%s)", w.Code, w.Body)
	}
	var resp enrollResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Address != "10.0.0.1/32" || resp.Peer.Endpoint != "vpn:51820" || resp.Peer.PublicKey != key(2) {
		t.Fatalf("unexpected enroll response: %+v", resp)
	}

	machines, _ := st.ListMachines()
	if len(machines) != 1 || machines[0].Status != store.StatusPending || machines[0].Address != "10.0.0.1" || machines[0].OwnerUID != "bob" {
		t.Fatalf("unexpected machine: %+v", machines)
	}
	ids, _ := st.EndpointIDsForMachine(machines[0].ID)
	if len(ids) != 1 || ids[0] != ep.ID {
		t.Errorf("endpoint not linked: %v", ids)
	}

	// Per-user cap reached → next enrollment is rejected.
	w2 := do(t, h, "POST", "/machines/enroll", cookies, url.Values{
		"csrf": {sess.CSRF}, "name": {"phone2"}, "public_key": {key(3)},
	})
	if w2.Code != http.StatusTooManyRequests {
		t.Errorf("cap: got %d, want 429", w2.Code)
	}
}

func TestSelfEnrollDisabled(t *testing.T) {
	_, h, cookies, csrf := testServer(t) // testServer has self_enroll off
	w := do(t, h, "POST", "/machines/enroll", cookies, url.Values{
		"csrf": {csrf}, "name": {"phone"}, "public_key": {key(1)},
	})
	if w.Code != http.StatusForbidden {
		t.Errorf("disabled enroll: got %d, want 403", w.Code)
	}
}

func TestCSRFRequired(t *testing.T) {
	_, h, cookies, _ := testServer(t)
	// POST without csrf token must be rejected.
	w := do(t, h, "POST", "/machines", cookies, url.Values{"name": {"x"}, "public_key": {key(1)}})
	if w.Code != http.StatusForbidden {
		t.Errorf("missing CSRF: got %d, want 403", w.Code)
	}
}

func TestAvatar(t *testing.T) {
	srv, h, cookies, _ := testServer(t) // admin session, uid "admin"

	// No cached photo yet → 404 (template falls back to the initial badge).
	if w := do(t, h, "GET", "/avatar/admin", cookies, nil); w.Code != http.StatusNotFound {
		t.Fatalf("avatar without photo: got %d, want 404", w.Code)
	}

	// Cache a photo for the admin, then the navbar avatar is served with its type.
	png := []byte{0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 1, 2, 3, 4}
	if err := srv.store.UpsertUserProfile("admin", "Admin User", png, "image/png"); err != nil {
		t.Fatal(err)
	}
	w := do(t, h, "GET", "/avatar/admin", cookies, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("avatar: got %d, want 200", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "image/png" {
		t.Errorf("content-type = %q, want image/png", ct)
	}
	if !bytes.Equal(w.Body.Bytes(), png) {
		t.Errorf("avatar body mismatch")
	}

	// A cached photo makes the navbar render an <img> instead of the initial.
	if d := do(t, h, "GET", "/", cookies, nil); !strings.Contains(d.Body.String(), `src="/avatar/admin"`) {
		t.Errorf("dashboard navbar missing avatar img:\n%s", d.Body)
	}

	// Fetching another user's avatar is 404 for a non-admin; admin may fetch any
	// (here it is simply absent → 404).
	if w := do(t, h, "GET", "/avatar/someoneelse", cookies, nil); w.Code != http.StatusNotFound {
		t.Errorf("absent other-user avatar: got %d, want 404", w.Code)
	}
}

// uploadDump posts a "wg show dump" body the way an endpoint's agent would.
func uploadDump(t *testing.T, h http.Handler, ep *store.Endpoint, dump string) {
	t.Helper()
	r := httptest.NewRequest("POST", fmt.Sprintf("/api/endpoints/%d/status", ep.ID), strings.NewReader(dump))
	r.Header.Set("Authorization", "Bearer "+ep.UploadToken)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusNoContent {
		t.Fatalf("status upload: got %d (%s)", w.Code, w.Body)
	}
}

// dumpLine renders one peer line of a wg dump with a fresh handshake.
func dumpLine(pubKey, allowedIPs string) string {
	return fmt.Sprintf("%s\t(none)\t203.0.113.9:1234\t%s\t%d\t10\t20\t25", pubKey, allowedIPs, time.Now().Unix())
}

func endpointByName(t *testing.T, srv *Server, name string) *store.Endpoint {
	t.Helper()
	eps, err := srv.store.ListEndpoints()
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range eps {
		if e.Name == name {
			return e
		}
	}
	t.Fatalf("no endpoint named %q", name)
	return nil
}

func statusFor(t *testing.T, srv *Server, name string) endpointStatus {
	t.Helper()
	statuses, err := srv.buildStatus()
	if err != nil {
		t.Fatal(err)
	}
	for _, es := range statuses {
		if es.E.Name == name {
			return es
		}
	}
	t.Fatalf("no status for endpoint %q", name)
	return endpointStatus{}
}

// TestAdoptUnexpectedPeer covers importing a config that predates the portal: a
// hub reports a public key nobody declared, and the drawer turns it into a
// machine in one step.
func TestAdoptUnexpectedPeer(t *testing.T) {
	srv, h, cookies, csrf := testServer(t)
	do(t, h, "POST", "/admin/endpoints", cookies, url.Values{
		"csrf": {csrf}, "name": {"paris"}, "public_key": {key(2)}, "host_port": {"vpn:51820"},
	})
	ep := mustEndpoint(t, srv)

	unknown := key(9)
	uploadDump(t, h, ep, dumpLine(unknown, "10.0.0.42/32"))

	if es := statusFor(t, srv, "paris"); es.Extra != 1 || es.Unlinked != 0 {
		t.Fatalf("want 1 extra / 0 unlinked, got %d/%d", es.Extra, es.Unlinked)
	}

	// The drawer offers the adopt form, prefilled with the address the hub
	// already announces (so the concentrator needs no change).
	w := do(t, h, "GET", fmt.Sprintf("/admin/peer?endpoint=%d&key=%s", ep.ID, url.QueryEscape(unknown)), cookies, nil)
	for _, want := range []string{"/admin/peers/adopt", `value="10.0.0.42"`} {
		if !strings.Contains(w.Body.String(), want) {
			t.Errorf("drawer missing %q:\n%s", want, w.Body)
		}
	}

	w = do(t, h, "POST", "/admin/peers/adopt", cookies, url.Values{
		"csrf": {csrf}, "endpoint": {fmt.Sprint(ep.ID)}, "key": {unknown},
		"owner_uid": {"alice"}, "name": {"legacy-laptop"}, "address": {"10.0.0.42"},
	})
	if w.Code != http.StatusSeeOther || !strings.Contains(w.Header().Get("Location"), "ok=") {
		t.Fatalf("adopt: got %d %q (%s)", w.Code, w.Header().Get("Location"), w.Body)
	}
	m, err := srv.store.MachineByPublicKey(unknown)
	if err != nil {
		t.Fatalf("adopted machine not found: %v", err)
	}
	if m.Status != store.StatusActive || m.Address != "10.0.0.42" || m.OwnerUID != "alice" || m.Name != "legacy-laptop" {
		t.Fatalf("adopted machine: %+v", m)
	}
	if ids, _ := srv.store.EndpointIDsForMachine(m.ID); len(ids) != 1 || ids[0] != ep.ID {
		t.Errorf("endpoint links: %v, want [%d]", ids, ep.ID)
	}

	// The drift is resolved: the peer is now expected, and online.
	if es := statusFor(t, srv, "paris"); es.Extra != 0 || es.OnlineN != 1 {
		t.Errorf("after adopt: extra=%d online=%d, want 0/1", es.Extra, es.OnlineN)
	}

	// Adopting again is refused rather than creating a duplicate.
	w = do(t, h, "POST", "/admin/peers/adopt", cookies, url.Values{
		"csrf": {csrf}, "endpoint": {fmt.Sprint(ep.ID)}, "key": {unknown},
		"owner_uid": {"bob"}, "name": {"dup"}, "address": {"10.0.0.43"},
	})
	if !strings.Contains(w.Header().Get("Location"), "err=") {
		t.Errorf("re-adopt should be rejected, got %q", w.Header().Get("Location"))
	}

	// A key the hub never reported cannot be adopted (the routes act only on
	// peers actually present in a report).
	w = do(t, h, "POST", "/admin/peers/adopt", cookies, url.Values{
		"csrf": {csrf}, "endpoint": {fmt.Sprint(ep.ID)}, "key": {key(7)},
		"owner_uid": {"bob"}, "name": {"ghost"}, "address": {"10.0.0.44"},
	})
	if w.Code != http.StatusNotFound {
		t.Errorf("adopt of an unreported key: got %d, want 404", w.Code)
	}
}

// TestLinkUnlinkedPeer covers the other half of the drift: the hub carries a key
// the portal knows, but the machine is not active on that endpoint.
func TestLinkUnlinkedPeer(t *testing.T) {
	srv, h, cookies, csrf := testServer(t)
	for i, name := range []string{"paris", "lyon"} {
		do(t, h, "POST", "/admin/endpoints", cookies, url.Values{
			"csrf": {csrf}, "name": {name}, "public_key": {key(byte(20 + i))}, "host_port": {"vpn:51820"},
		})
	}
	paris, lyon := endpointByName(t, srv, "paris"), endpointByName(t, srv, "lyon")

	// An active machine on paris only, which lyon's hub also carries.
	mKey := key(1)
	do(t, h, "POST", "/admin/machines", cookies, url.Values{
		"csrf": {csrf}, "owner_uid": {"alice"}, "name": {"laptop"}, "public_key": {mKey},
		"address": {"10.0.0.5"}, "endpoint_ids": {fmt.Sprint(paris.ID)},
	})
	uploadDump(t, h, lyon, dumpLine(mKey, "10.0.0.5/32"))

	es := statusFor(t, srv, "lyon")
	if es.Unlinked != 1 || es.Extra != 0 {
		t.Fatalf("lyon: want 1 unlinked / 0 extra, got %d/%d", es.Unlinked, es.Extra)
	}
	if es.Peers[0].State != statePeerUnlinked || es.Peers[0].Pending {
		t.Fatalf("peer state: %q pending=%v", es.Peers[0].State, es.Peers[0].Pending)
	}

	// The drawer offers to link, keeping the address already assigned.
	w := do(t, h, "GET", fmt.Sprintf("/admin/peer?endpoint=%d&key=%s", lyon.ID, url.QueryEscape(mKey)), cookies, nil)
	for _, want := range []string{"/admin/peers/link", `value="10.0.0.5"`} {
		if !strings.Contains(w.Body.String(), want) {
			t.Errorf("drawer missing %q:\n%s", want, w.Body)
		}
	}

	w = do(t, h, "POST", "/admin/peers/link", cookies, url.Values{
		"csrf": {csrf}, "endpoint": {fmt.Sprint(lyon.ID)}, "key": {mKey}, "address": {"10.0.0.5"},
	})
	if w.Code != http.StatusSeeOther || !strings.Contains(w.Header().Get("Location"), "ok=") {
		t.Fatalf("link: got %d %q (%s)", w.Code, w.Header().Get("Location"), w.Body)
	}
	m, _ := srv.store.MachineByPublicKey(mKey)
	ids, _ := srv.store.EndpointIDsForMachine(m.ID)
	if len(ids) != 2 || m.Address != "10.0.0.5" {
		t.Errorf("after link: address=%q endpoints=%v, want 10.0.0.5 on both", m.Address, ids)
	}
	if es := statusFor(t, srv, "lyon"); es.Unlinked != 0 || es.OnlineN != 1 {
		t.Errorf("lyon after link: unlinked=%d online=%d, want 0/1", es.Unlinked, es.OnlineN)
	}

	// Same route approves a machine still pending, which the hub already carries.
	pKey := key(4)
	do(t, h, "POST", "/machines", cookies, url.Values{"csrf": {csrf}, "name": {"phone"}, "public_key": {pKey}})
	uploadDump(t, h, paris, dumpLine(pKey, "10.0.0.6/32"))
	es = statusFor(t, srv, "paris")
	var pending *peerStatus
	for i := range es.Peers {
		if es.Peers[i].PublicKey == pKey {
			pending = &es.Peers[i]
		}
	}
	if pending == nil || pending.State != statePeerUnlinked || !pending.Pending {
		t.Fatalf("pending peer not reported as unlinked+pending: %+v", pending)
	}
	w = do(t, h, "POST", "/admin/peers/link", cookies, url.Values{
		"csrf": {csrf}, "endpoint": {fmt.Sprint(paris.ID)}, "key": {pKey}, "address": {"10.0.0.6"},
	})
	if !strings.Contains(w.Header().Get("Location"), "ok=") {
		t.Fatalf("approve via link: %q (%s)", w.Header().Get("Location"), w.Body)
	}
	pm, _ := srv.store.MachineByPublicKey(pKey)
	if pm.Status != store.StatusActive || pm.Address != "10.0.0.6" {
		t.Errorf("approved machine: %+v", pm)
	}
}

func TestAuditLimit(t *testing.T) {
	cases := []struct {
		raw  string
		want int
	}{
		{"", 300},
		{"300", 300},
		{"1000", 1000},
		{"5000", 5000},
		{"99999", 300}, // not offered: fall back rather than scan the whole table
		{"0", 300},
		{"-1", 300},
		{"abc", 300},
	}
	for _, tc := range cases {
		if got := auditLimit(tc.raw); got != tc.want {
			t.Errorf("auditLimit(%q) = %d, want %d", tc.raw, got, tc.want)
		}
	}
}

func TestAuditPage(t *testing.T) {
	_, h, cookies, csrf := testServer(t)
	// Any admin action records an audit entry.
	do(t, h, "POST", "/admin/endpoints", cookies, url.Values{
		"csrf": {csrf}, "name": {"paris"}, "public_key": {key(2)}, "host_port": {"vpn:51820"},
	})

	w := do(t, h, "GET", "/admin/audit", cookies, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /admin/audit: got %d", w.Code)
	}
	body := w.Body.String()
	// The filter box and per-row haystack drive the client-side search.
	for _, want := range []string{`id="a-search"`, `class="a-item`, "data-haystack=", "paris"} {
		if !strings.Contains(body, want) {
			t.Errorf("audit page missing %q", want)
		}
	}
	// Every offered limit is reachable as a link.
	for _, l := range auditLimits {
		if !strings.Contains(body, fmt.Sprintf("/admin/audit?limit=%d", l)) {
			t.Errorf("audit page missing the limit-%d link", l)
		}
	}

	// A rejected limit still renders the page (falling back to the default).
	if w := do(t, h, "GET", "/admin/audit?limit=99999", cookies, nil); w.Code != http.StatusOK {
		t.Errorf("GET /admin/audit?limit=99999: got %d", w.Code)
	}

	// The page is admin-only.
	srv2, h2, _, _ := testServer(t)
	rec := httptest.NewRecorder()
	bob, _ := srv2.sess.Issue(rec, "bob", "", false, false)
	_ = bob
	if w := do(t, h2, "GET", "/admin/audit", rec.Result().Cookies(), nil); w.Code == http.StatusOK {
		t.Error("a non-admin session reached the audit page")
	}
}

func TestMetricsBuildInfoAndLabelEscaping(t *testing.T) {
	_, h, cookies, csrf := testServer(t)
	// A quote in the endpoint name must be escaped exactly once.
	do(t, h, "POST", "/admin/endpoints", cookies, url.Values{
		"csrf": {csrf}, "name": {`pa"ris`}, "public_key": {key(2)}, "host_port": {"vpn:51820"},
	})

	w := do(t, h, "GET", "/metrics", cookies, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /metrics: got %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, `wg_build_info{version="dev"} 1`) {
		t.Errorf("/metrics missing wg_build_info\n%s", body)
	}
	if !strings.Contains(body, `wg_peers_online{endpoint="pa\"ris"}`) {
		t.Errorf("endpoint label is not escaped as Prometheus expects\n%s", body)
	}
	if strings.Contains(body, `\\"`) {
		t.Errorf("endpoint label is double-escaped\n%s", body)
	}
}
func TestCSPRestrictsFormAction(t *testing.T) {
	_, h, _, _ := testServer(t)
	csp := do(t, h, "GET", "/login", nil, nil).Header().Get("Content-Security-Policy")
	// default-src does not cover form-action, so it must be spelled out: the login
	// form posts a password and every mutating form posts a CSRF token.
	if !strings.Contains(csp, "form-action 'self'") {
		t.Errorf("CSP is missing form-action 'self': %q", csp)
	}
}

// The fleet status is the most expensive read in the portal and has three
// concurrent consumers, so it is cached for a few seconds.
func TestStatusCache(t *testing.T) {
	srv, h, cookies, csrf := testServer(t)
	do(t, h, "POST", "/admin/endpoints", cookies, url.Values{
		"csrf": {csrf}, "name": {"paris"}, "public_key": {key(2)}, "host_port": {"vpn:51820"},
	})

	first, err := srv.status()
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 1 {
		t.Fatalf("got %d endpoints, want 1", len(first))
	}

	// A second endpoint appears, but the cached status is served as is.
	if err := srv.store.CreateEndpoint(&store.Endpoint{
		Name: "ams", PublicKey: key(3), HostPort: "ams:51820", UploadToken: "t",
	}); err != nil {
		t.Fatal(err)
	}
	cached, err := srv.status()
	if err != nil {
		t.Fatal(err)
	}
	if len(cached) != 1 {
		t.Errorf("got %d endpoints, want the cached 1", len(cached))
	}

	// Once the entry ages past the TTL it is rebuilt.
	srv.statusMu.Lock()
	srv.statusCachedAt = time.Now().Add(-statusCacheTTL - time.Second)
	srv.statusMu.Unlock()
	fresh, err := srv.status()
	if err != nil {
		t.Fatal(err)
	}
	if len(fresh) != 2 {
		t.Errorf("got %d endpoints after the TTL, want 2", len(fresh))
	}
}
