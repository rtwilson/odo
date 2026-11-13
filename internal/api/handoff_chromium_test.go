package api

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"sync/atomic"
	"testing"
	"time"
)

// Optional real-browser regression, using Chromium's local pipe protocol so
// there is no debug TCP listener, browser library, or shared user profile.
// Run with ODO_TEST_CHROMIUM=/usr/bin/chromium-browser go test ./internal/api
// -run TestChromiumAutomaticHandoff -count=1.
func TestChromiumAutomaticHandoff(t *testing.T) {
	binary := os.Getenv("ODO_TEST_CHROMIUM")
	if binary == "" {
		t.Skip("set ODO_TEST_CHROMIUM to run the real-browser regression")
	}
	d := newDeliveryHarnessWithSite(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, vendorBodyMarker+" "+r.URL.RequestURI())
	}))
	var confirmations atomic.Int32
	listener := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host == "odo.example" && r.URL.Path == handoffConfirmPath && r.Method == "POST" {
			confirmations.Add(1)
		}
		d.routes.ServeHTTP(w, r)
	}))
	defer listener.Close()
	localURL, _ := url.Parse(listener.URL)
	sum := sha256.Sum256(listener.Certificate().RawSubjectPublicKeyInfo)
	c := newHandoffChromium(t, binary, localURL.Host, base64.StdEncoding.EncodeToString(sum[:]))
	start := "https://odo.example/launch?" + url.Values{"url": {d.target}}.Encode()
	c.call("Page.navigate", map[string]any{"url": start})
	c.waitFor(`document.querySelector('input[name="password"]') !== null`)
	// Only the initial login is submitted by the test. No confirmation button
	// or handoff POST is driven by the test: the production script must do it.
	c.evaluate(`document.querySelector('[name="username"]').value='alice';document.querySelector('[name="password"]').value='correct horse battery';document.forms[0].requestSubmit();true`)
	marker := `location.hostname !== 'odo.example' && document.body.textContent.includes('vendor-body-marker')`
	c.waitFor(marker)
	if confirmations.Load() != 1 {
		t.Fatal("login did not produce exactly one automatic confirmation")
	}
	// Repeat launches with a live host grant: no further confirmation/tickets.
	for i := 0; i < 2; i++ {
		c.call("Page.navigate", map[string]any{"url": start})
		c.waitFor(marker)
	}
	if confirmations.Load() != 1 {
		t.Fatal("live grant did not skip handoff")
	}
	d.h.state.mu.Lock()
	for key, g := range d.h.state.grants {
		g.expires = time.Now().Add(-time.Second)
		d.h.state.grants[key] = g
	}
	d.h.state.mu.Unlock()
	c.call("Page.navigate", map[string]any{"url": "https://" + d.authority + "/private?escaped=%2F&space=a%20b"})
	c.waitFor(marker)
	if confirmations.Load() != 2 {
		t.Fatal("expired grant did not re-handoff automatically")
	}
	if !c.evaluate(`document.body.textContent.includes("/private?escaped=%2F&space=a%20b")`) {
		t.Fatal("real-browser navigation changed query")
	}
	// Back/forward traverses completed entries without replaying the automatic
	// POST or requiring a second confirmation click.
	var history struct {
		CurrentIndex int `json:"currentIndex"`
		Entries      []struct {
			ID int `json:"id"`
		} `json:"entries"`
	}
	json.Unmarshal(c.call("Page.getNavigationHistory", nil), &history)
	if history.CurrentIndex > 0 {
		before := confirmations.Load()
		c.call("Page.navigateToHistoryEntry", map[string]any{"entryId": history.Entries[history.CurrentIndex-1].ID})
		c.waitFor(marker)
		c.call("Page.navigateToHistoryEntry", map[string]any{"entryId": history.Entries[history.CurrentIndex].ID})
		c.waitFor(marker)
		if confirmations.Load() != before {
			t.Fatal("back/forward replayed confirmation")
		}
	}
}

type handoffChromium struct {
	t       *testing.T
	input   io.Writer
	output  *bufio.Reader
	id      int
	session string
}

func newHandoffChromium(t *testing.T, binary, address, spki string) *handoffChromium {
	t.Helper()
	toChild, input, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	output, fromChild, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	cmd := exec.CommandContext(ctx, binary, "--headless", "--disable-gpu", "--no-first-run", "--no-default-browser-check", "--no-proxy-server", "--remote-debugging-pipe", "--user-data-dir="+t.TempDir(), "--host-resolver-rules=MAP odo.example:443 "+address+", MAP *.proxy.example:443 "+address, "--ignore-certificate-errors-spki-list="+spki, "about:blank")
	cmd.ExtraFiles = []*os.File{toChild, fromChild}
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	toChild.Close()
	fromChild.Close()
	t.Cleanup(func() {
		// Ask Chromium to shut down its children and flush its disposable profile.
		_, _ = input.Write(append([]byte(`{"id":1000000,"method":"Browser.close"}`), 0))
		cmd.Wait()
		cancel()
		input.Close()
		output.Close()
	})
	c := &handoffChromium{t: t, input: input, output: bufio.NewReader(output)}
	var target struct {
		TargetID string `json:"targetId"`
	}
	json.Unmarshal(c.call("Target.createTarget", map[string]any{"url": "about:blank"}), &target)
	var attached struct {
		SessionID string `json:"sessionId"`
	}
	json.Unmarshal(c.call("Target.attachToTarget", map[string]any{"targetId": target.TargetID, "flatten": true}), &attached)
	c.session = attached.SessionID
	c.call("Page.enable", nil)
	return c
}

func (c *handoffChromium) call(method string, params any) json.RawMessage {
	c.t.Helper()
	c.id++
	message := map[string]any{"id": c.id, "method": method, "params": params}
	if params == nil {
		delete(message, "params")
	}
	if c.session != "" {
		message["sessionId"] = c.session
	}
	encoded, _ := json.Marshal(message)
	if _, err := c.input.Write(append(encoded, 0)); err != nil {
		c.t.Fatal(err)
	}
	for {
		raw, err := c.output.ReadBytes(0)
		if err != nil {
			c.t.Fatalf("Chromium pipe ended during %s: %v", method, err)
		}
		var reply struct {
			ID     int             `json:"id"`
			Result json.RawMessage `json:"result"`
			Error  json.RawMessage `json:"error"`
		}
		if err := json.Unmarshal(raw[:len(raw)-1], &reply); err != nil {
			c.t.Fatal(err)
		}
		if reply.ID != c.id {
			continue
		}
		if len(reply.Error) > 0 && method != "Runtime.evaluate" {
			c.t.Fatalf("Chromium %s: %s", method, reply.Error)
		}
		return reply.Result
	}
}

func (c *handoffChromium) evaluate(expression string) bool {
	c.t.Helper()
	var reply struct {
		Result struct {
			Value bool `json:"value"`
		} `json:"result"`
	}
	json.Unmarshal(c.call("Runtime.evaluate", map[string]any{"expression": expression, "returnByValue": true}), &reply)
	return reply.Result.Value
}

func (c *handoffChromium) waitFor(expression string) {
	c.t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if c.evaluate(expression) {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	// No browser URLs, queries, credentials or page bodies in failure output.
	c.t.Fatal("Chromium navigation did not complete")
}
