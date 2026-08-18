package web

import (
	"embed"
	"fmt"
	"html/template"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/wgroster/wgroster/internal/auth"
)

//go:embed templates/*.html
var templatesFS embed.FS

// fullPages share the layout; partials are rendered standalone (htmx fragments).
var fullPages = []string{
	"login", "dashboard", "machine_config",
	"admin_machines", "admin_endpoints", "admin_status", "admin_audit",
}

var partials = []string{"status_table", "peer_drawer", "dashboard_list"}

var (
	pageTmpls    = map[string]*template.Template{}
	partialTmpls = map[string]*template.Template{}
)

var funcs = template.FuncMap{
	"humanBytes": humanBytes,
	"ago":        ago,
	"since":      since,
	"exact":      exact,
	"upper":      strings.ToUpper,
	"lower":      strings.ToLower,
	"initial":    initial,
	"sparkline":  sparkline,
	"shortIPs":   shortIPs,
}

// sparkline renders a tiny inline SVG line chart from numeric samples. The
// output is built from numbers only (no user input), so it is safe as HTML and
// fits the strict CSP (inline SVG markup, no script).
func sparkline(vals []int64) template.HTML {
	if len(vals) < 2 {
		return ""
	}
	var max int64
	for _, v := range vals {
		if v > max {
			max = v
		}
	}
	w := 120.0
	if len(vals) > 60 {
		w = float64(len(vals) * 2)
	}
	const h = 28.0
	const pad = 3.0 // keep the line off the top/bottom edges
	step := w / float64(len(vals)-1)
	scaleY := func(v int64) float64 {
		if max == 0 { // all-zero series → flat line in the middle
			return h / 2
		}
		return h - pad - (float64(v)/float64(max))*(h-2*pad)
	}
	var b strings.Builder
	// Color is inherited (currentColor) from the wrapping element.
	fmt.Fprintf(&b, `<svg width="%.0f" height="%.0f" viewBox="0 0 %.0f %.0f" preserveAspectRatio="none"><polyline fill="none" stroke="currentColor" stroke-width="1.5" vector-effect="non-scaling-stroke" points="`, w, h, w, h)
	for i, v := range vals {
		fmt.Fprintf(&b, "%.1f,%.1f ", float64(i)*step, scaleY(v))
	}
	b.WriteString(`"/></svg>`)
	return template.HTML(b.String())
}

// since renders a full wg-style relative duration, e.g.
// "4 days, 15 hours, 16 minutes, 41 seconds ago". Zero (intermediate) units are
// skipped, matching "wg show". Returns "never" for the zero time.
func since(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	secs := int64(time.Since(t).Seconds())
	if secs < 0 {
		secs = 0
	}
	days, secs := secs/86400, secs%86400
	hours, secs := secs/3600, secs%3600
	mins, secs := secs/60, secs%60

	var parts []string
	add := func(n int64, unit string) {
		if n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s%s", n, unit, plural(n)))
		}
	}
	add(days, "day")
	add(hours, "hour")
	add(mins, "minute")
	if secs > 0 || len(parts) == 0 {
		parts = append(parts, fmt.Sprintf("%d second%s", secs, plural(secs)))
	}
	return strings.Join(parts, ", ") + " ago"
}

// exact renders the absolute timestamp in the server's local zone, e.g.
// "Fri May 29 08:01:21 CEST 2026". Empty for the zero time (for tooltips).
func exact(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format("Mon Jan _2 15:04:05 MST 2006")
}

func plural(n int64) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// shortIPs drops the prefix length from single-host entries of a comma-separated
// allowed-ips list ("10.0.0.7/32, fd00::7/128" -> "10.0.0.7, fd00::7"). In this
// model a client address is always a single host, so the suffix is pure noise on
// every row; a real subnet keeps its prefix, where the length is the
// information. Entries that do not parse are passed through untouched.
func shortIPs(list string) string {
	parts := strings.Split(list, ",")
	for i, part := range parts {
		part = strings.TrimSpace(part)
		parts[i] = part
		if pfx, err := netip.ParsePrefix(part); err == nil && pfx.Bits() == pfx.Addr().BitLen() {
			parts[i] = pfx.Addr().String()
		}
	}
	return strings.Join(parts, ", ")
}

// initial returns the upper-cased first character of s (for avatar badges).
func initial(s string) string {
	for _, r := range s {
		return strings.ToUpper(string(r))
	}
	return "?"
}

func loadTemplates() error {
	// Every page is parsed with the layout and all partials, so a page can embed
	// the same partial an htmx fragment endpoint serves (e.g. the dashboard
	// machine list) instead of keeping a second copy of the markup.
	files := []string{"templates/layout.html"}
	for _, p := range partials {
		files = append(files, "templates/"+p+".html")
	}
	for _, p := range fullPages {
		t, err := template.New(p).Funcs(funcs).ParseFS(templatesFS,
			append(files, "templates/"+p+".html")...)
		if err != nil {
			return fmt.Errorf("parse page %s: %w", p, err)
		}
		pageTmpls[p] = t
	}
	for _, p := range partials {
		t, err := template.New(p).Funcs(funcs).ParseFS(templatesFS, "templates/"+p+".html")
		if err != nil {
			return fmt.Errorf("parse partial %s: %w", p, err)
		}
		partialTmpls[p] = t
	}
	return nil
}

// pageData is the common envelope passed to every full page.
type pageData struct {
	Title      string
	Active     string
	Session    *auth.Session
	Flash      string
	Error      string
	AssetV     string // asset version for cache-busting /static URLs
	SelfEnroll bool   // whether self-enrollment is enabled
	HasPhoto   bool   // the logged-in user has a cached avatar (/avatar/{uid})
	Version    string // release version shown in the footer (empty for dev builds)
	Data       any
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, page, title, active string, data any) {
	t, ok := pageTmpls[page]
	if !ok {
		http.Error(w, "unknown page", http.StatusInternalServerError)
		return
	}
	sess := sessionFrom(r)
	hasPhoto := false
	if sess != nil {
		if _, hp, _, _, err := s.store.UserProfileMeta(sess.UID); err == nil {
			hasPhoto = hp
		}
	}
	// Show the version in the footer only for a real release build.
	version := s.version
	if version == "dev" {
		version = ""
	}
	pd := pageData{
		Title:      title,
		Active:     active,
		Session:    sess,
		Flash:      r.URL.Query().Get("ok"),
		Error:      r.URL.Query().Get("err"),
		AssetV:     s.assetVersion,
		SelfEnroll: s.cfg.SelfEnroll,
		HasPhoto:   hasPhoto,
		Version:    version,
		Data:       data,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.ExecuteTemplate(w, "layout", pd); err != nil {
		s.serverError(w, err)
	}
}

func (s *Server) renderPartial(w http.ResponseWriter, page string, data any) {
	t, ok := partialTmpls[page]
	if !ok {
		http.Error(w, "unknown partial", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.ExecuteTemplate(w, page, data); err != nil {
		s.serverError(w, err)
	}
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for x := n / unit; x >= unit; x /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

// ago renders a relative duration since t (zero time -> "never").
func ago(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds ago", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
}
