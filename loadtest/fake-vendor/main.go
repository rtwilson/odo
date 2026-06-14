package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"
)

func main() {
	addr := env("FAKE_VENDOR_ADDR", "127.0.0.1:9090")
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", home)
	mux.HandleFunc("GET /section/science", section)
	mux.HandleFunc("GET /article/123", article)
	mux.HandleFunc("GET /assets/app.css", css)
	mux.HandleFunc("GET /assets/app.js", js)
	mux.HandleFunc("GET /api/search", search)
	mux.HandleFunc("GET /api/user/status", status)
	mux.HandleFunc("GET /redirect-to-article", redirect)
	mux.HandleFunc("GET /slow", slow)

	log.Printf("fake vendor listening on http://%s", addr)
	if err := http.ListenAndServe(addr, requestLog(mux)); err != nil {
		log.Fatal(err)
	}
}

func env(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func requestLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s %s", r.Method, r.URL.RequestURI(), time.Since(start).Round(time.Millisecond))
	})
}

func setVendorCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     "fake_vendor_session",
		Value:    "local-loadtest",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

func home(w http.ResponseWriter, r *http.Request) {
	setVendorCookie(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Fake Vendor</title>
  <link rel="stylesheet" href="/assets/app.css">
  <script src="/assets/app.js" defer></script>
</head>
<body>
  <header>
    <h1>Fake Vendor</h1>
    <nav>
      <a href="/section/science">Science section</a>
      <a href="http://127.0.0.1:9090/article/123">Absolute article link</a>
      <a href="/redirect-to-article">Redirect to article</a>
    </nav>
  </header>
  <main>
    <form action="/api/search" method="get">
      <label>Search <input name="q" value="test"></label>
      <button>Search</button>
    </form>
    <p id="status">Loading status...</p>
  </main>
</body>
</html>`)
}

func section(w http.ResponseWriter, r *http.Request) {
	setVendorCookie(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Science - Fake Vendor</title><link rel="stylesheet" href="/assets/app.css"></head>
<body>
  <h1>Science</h1>
  <ul>
    <li><a href="/article/123">Useful article</a></li>
    <li><a href="/slow?ms=250">Slow endpoint</a></li>
  </ul>
  <script src="/assets/app.js"></script>
</body>
</html>`)
}

func article(w http.ResponseWriter, r *http.Request) {
	setVendorCookie(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Article 123</title><link rel="stylesheet" href="/assets/app.css"></head>
<body>
  <article>
    <h1>Article 123</h1>
    <p>This page includes root-relative assets, an absolute link, cookies, and dynamic API calls.</p>
    <a href="/">Back to homepage</a>
    <a href="http://127.0.0.1:9090/api/search?q=article">Absolute search API</a>
  </article>
  <script src="/assets/app.js"></script>
</body>
</html>`)
}

func css(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	fmt.Fprint(w, `body { font-family: system-ui, sans-serif; margin: 2rem; } a { margin-right: 1rem; }`)
}

func js(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	fmt.Fprint(w, `fetch('/api/user/status').then(r => r.json()).then(data => {
  const el = document.querySelector('#status');
  if (el) el.textContent = 'Status: ' + data.status;
});
fetch('/api/search?q=dynamic').then(r => r.json()).then(() => {});`)
}

func search(w http.ResponseWriter, r *http.Request) {
	setVendorCookie(w)
	w.Header().Set("Content-Type", "application/json")
	query := r.URL.Query().Get("q")
	if query == "" {
		query = "test"
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"query": query,
		"results": []map[string]string{
			{"title": "Article 123", "url": "/article/123"},
			{"title": "Science section", "url": "/section/science"},
		},
	})
}

func status(w http.ResponseWriter, r *http.Request) {
	setVendorCookie(w)
	w.Header().Set("Content-Type", "application/json")
	_, hasCookie := r.Cookie("fake_vendor_session")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":     "ok",
		"has_cookie": hasCookie,
	})
}

func redirect(w http.ResponseWriter, r *http.Request) {
	setVendorCookie(w)
	http.Redirect(w, r, "/article/123", http.StatusFound)
}

func slow(w http.ResponseWriter, r *http.Request) {
	ms, err := strconv.Atoi(r.URL.Query().Get("ms"))
	if err != nil || ms < 0 {
		ms = 500
	}
	if ms > 5000 {
		ms = 5000
	}
	time.Sleep(time.Duration(ms) * time.Millisecond)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok", "slept_ms": ms})
}
