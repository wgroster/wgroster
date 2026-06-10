// Command screenshots drives a headless Chrome to capture the UI for the README.
//
//	go run . -url http://127.0.0.1:8123 -out ../../docs/screenshots
//
// Usually invoked via scripts/screenshots.sh (which seeds a fake DB and runs
// the server). Requires Google Chrome / Chromium installed.
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/chromedp/chromedp"
)

func main() {
	url := flag.String("url", "http://127.0.0.1:8123", "base URL of a running wgroster")
	out := flag.String("out", "docs/screenshots", "output directory for PNGs")
	flag.Parse()

	if err := os.MkdirAll(*out, 0o755); err != nil {
		log.Fatal(err)
	}

	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.WindowSize(1280, 900),
	)
	alloc, cancelAlloc := chromedp.NewExecAllocator(context.Background(), opts...)
	defer cancelAlloc()
	ctx, cancelCtx := chromedp.NewContext(alloc)
	defer cancelCtx()
	ctx, cancelTimeout := context.WithTimeout(ctx, 120*time.Second)
	defer cancelTimeout()

	save := func(name string, actions ...chromedp.Action) {
		var buf []byte
		acts := append(actions, chromedp.FullScreenshot(&buf, 95))
		if err := chromedp.Run(ctx, acts...); err != nil {
			log.Fatalf("%s: %v", name, err)
		}
		if err := os.WriteFile(filepath.Join(*out, name), buf, 0o644); err != nil {
			log.Fatal(err)
		}
		log.Printf("wrote %s (%d KiB)", name, len(buf)/1024)
	}

	// Login page (before authenticating).
	save("login.png",
		chromedp.Navigate(*url+"/login"),
		chromedp.WaitVisible(`input[name="uid"]`),
		chromedp.Sleep(300*time.Millisecond),
	)

	// Authenticate.
	if err := chromedp.Run(ctx,
		chromedp.Navigate(*url+"/login"),
		chromedp.WaitVisible(`input[name="uid"]`),
		chromedp.SendKeys(`input[name="uid"]`, "admin"),
		chromedp.SendKeys(`input[name="password"]`, "admin"),
		chromedp.Submit(`input[name="password"]`),
		chromedp.WaitVisible(`nav`),
	); err != nil {
		log.Fatalf("login: %v", err)
	}

	save("dashboard.png",
		chromedp.Navigate(*url+"/"), chromedp.WaitVisible(`h1`), chromedp.Sleep(400*time.Millisecond))
	save("machines.png",
		chromedp.Navigate(*url+"/admin/machines"), chromedp.WaitVisible(`section.m-group`), chromedp.Sleep(400*time.Millisecond))
	save("endpoints.png",
		chromedp.Navigate(*url+"/admin/endpoints"), chromedp.WaitVisible(`.e-item`), chromedp.Sleep(400*time.Millisecond))
	save("status.png",
		chromedp.Navigate(*url+"/admin/status"), chromedp.WaitVisible(`tr[hx-get]`), chromedp.Sleep(700*time.Millisecond))
	save("audit.png",
		chromedp.Navigate(*url+"/admin/audit"), chromedp.WaitVisible(`table`), chromedp.Sleep(300*time.Millisecond))

	// Peer detail drawer (open the rich peer "macbook-pro").
	save("status-drawer.png",
		chromedp.Navigate(*url+"/admin/status"),
		chromedp.WaitVisible(`tr[hx-get]`),
		chromedp.Click(`//tr[contains(., "macbook-pro")]`, chromedp.BySearch),
		chromedp.WaitVisible(`#peer-drawer-body h4`),
		chromedp.Sleep(900*time.Millisecond),
	)

	// Dark theme (status).
	save("status-dark.png",
		chromedp.Navigate(*url+"/"),
		chromedp.Evaluate(`localStorage.setItem('wg-theme','dark')`, nil),
		chromedp.Navigate(*url+"/admin/status"),
		chromedp.WaitVisible(`tr[hx-get]`),
		chromedp.Sleep(700*time.Millisecond),
	)
}
