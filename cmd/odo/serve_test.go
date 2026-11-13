package main

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func startServe(t *testing.T, handler http.Handler, grace time.Duration) (string, context.CancelFunc, chan error) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- serve(ctx, newHTTPServer(handler), listener, grace)
	}()
	return "http://" + listener.Addr().String(), cancel, done
}

// A stop signal lets an in-flight request complete, refuses new connections
// and returns cleanly, so deferred database/log closes run.
func TestServeDrainsInFlightRequestsOnStop(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	base, stop, done := startServe(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-release
		_, _ = io.WriteString(w, "finished")
	}), 5*time.Second)
	result := make(chan string, 1)
	go func() {
		response, err := http.Get(base + "/slow")
		if err != nil {
			result <- "error: " + err.Error()
			return
		}
		defer response.Body.Close()
		body, _ := io.ReadAll(response.Body)
		result <- string(body)
	}()
	<-entered
	stop()
	// Shutdown closes the listener before waiting for active requests.
	deadline := time.Now().Add(2 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", base[len("http://"):], 100*time.Millisecond)
		if err != nil {
			break
		}
		conn.Close()
		if time.Now().After(deadline) {
			t.Fatal("listener still accepting after stop")
		}
		time.Sleep(10 * time.Millisecond)
	}
	close(release)
	if got := <-result; got != "finished" {
		t.Fatalf("in-flight request: %q", got)
	}
	if err := <-done; err != nil {
		t.Fatalf("clean stop returned %v", err)
	}
}

// A request that outlives the grace period is cut off and reported.
func TestServeReportsShutdownTimeout(t *testing.T) {
	entered := make(chan struct{})
	base, stop, done := startServe(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-r.Context().Done()
	}), 50*time.Millisecond)
	go func() {
		if response, err := http.Get(base + "/hang"); err == nil {
			response.Body.Close()
		}
	}()
	<-entered
	stop()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("shutdown timeout not reported")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serve did not return after the grace period")
	}
}

func TestServerLimitsHeadersButNotTransfers(t *testing.T) {
	server := newHTTPServer(http.NotFoundHandler())
	if server.ReadHeaderTimeout != readHeaderTimeout || server.IdleTimeout != idleTimeout || server.MaxHeaderBytes != maxHeaderBytes {
		t.Fatal("server limits not applied")
	}
	// Long vendor downloads and uploads must not be cut off by a global timeout.
	if server.ReadTimeout != 0 || server.WriteTimeout != 0 || shutdownGrace >= 10*time.Second {
		t.Fatal("unexpected transfer timeout or grace beyond the container stop timeout")
	}
}

// Oversized request headers are refused before reaching any handler, while a
// maximum-size launch query still fits.
func TestServerRejectsOversizedHeaders(t *testing.T) {
	reached := make(chan struct{}, 4)
	base, stop, done := startServe(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached <- struct{}{}
	}), time.Second)
	defer func() { stop(); <-done }()
	send := func(path, header string) int {
		t.Helper()
		conn, err := net.Dial("tcp", strings.TrimPrefix(base, "http://"))
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		_, _ = io.WriteString(conn, "GET "+path+" HTTP/1.1\r\nHost: odo.example\r\n"+header+"Connection: close\r\n\r\n")
		response, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		return response.StatusCode
	}
	if status := send("/launch?url="+strings.Repeat("a", 16<<10), ""); status != http.StatusOK {
		t.Fatalf("16 KiB launch query rejected: %d", status)
	}
	if status := send("/", "X-Padding: "+strings.Repeat("a", 2*maxHeaderBytes)+"\r\n"); status != http.StatusRequestHeaderFieldsTooLarge {
		t.Fatalf("oversized header: %d", status)
	}
	if len(reached) != 1 {
		t.Fatalf("handler calls: %d, want 1", len(reached))
	}
}
