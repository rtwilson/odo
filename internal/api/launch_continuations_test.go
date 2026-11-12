package api

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"example.org/odo/internal/auth/local"
)

func TestLaunchContinuationsBindingExpiryAndCapacity(t *testing.T) {
	store := newLaunchContinuations()
	now := time.Now()
	token, err := store.create("https://vendor.example/private", "browser", now)
	if err != nil {
		t.Fatal(err)
	}
	if !validLaunchToken(token) {
		t.Fatal("invalid generated token")
	}
	if _, found := store.entries[token]; found {
		t.Fatal("store retained plaintext token")
	}
	if _, ok := store.consume(token, "other browser", now); ok {
		t.Fatal("accepted swapped browser nonce")
	}
	if target, ok := store.consume(token, "browser", now); !ok || target != "https://vendor.example/private" {
		t.Fatalf("legitimate redemption: %q %v", target, ok)
	}
	if _, ok := store.consume(token, "browser", now); ok {
		t.Fatal("accepted replay")
	}
	var expiring string
	for range maxLaunchContinuations {
		expiring, err = store.create("https://vendor.example/", "browser", now)
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, ok := store.consume(expiring, "browser", now.Add(launchContinuationTTL)); ok {
		t.Fatal("accepted expired token")
	}
}

// Anonymous floods must not deny launch-then-login to everyone: a full store
// evicts its oldest entry, stays bounded, and keeps accepting new patrons.
func TestLaunchContinuationsFloodEvictsOldest(t *testing.T) {
	store := newLaunchContinuations()
	now := time.Now()
	oldest, err := store.create("https://vendor.example/first", "early", now)
	if err != nil {
		t.Fatal(err)
	}
	for i := range maxLaunchContinuations + 50 {
		if _, err := store.create("https://vendor.example/", "flood", now.Add(time.Duration(i+1)*time.Millisecond)); err != nil {
			t.Fatalf("flood entry %d refused: %v", i, err)
		}
	}
	if len(store.entries) != maxLaunchContinuations {
		t.Fatalf("store not bounded: %d", len(store.entries))
	}
	if _, ok := store.consume(oldest, "early", now.Add(time.Second)); ok {
		t.Fatal("oldest entry survived capacity eviction")
	}
	patron, err := store.create("https://vendor.example/patron", "patron", now.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if target, ok := store.consume(patron, "patron", now.Add(3*time.Second)); !ok || target != "https://vendor.example/patron" {
		t.Fatal("new patron continuation was not usable during a flood")
	}
}

func TestLaunchContinuationConcurrentRedemption(t *testing.T) {
	store := newLaunchContinuations()
	now := time.Now()
	token, err := store.create("https://vendor.example/", "browser", now)
	if err != nil {
		t.Fatal(err)
	}
	var successes atomic.Int32
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, ok := store.consume(token, "browser", now); ok {
				successes.Add(1)
			}
		}()
	}
	wg.Wait()
	if successes.Load() != 1 {
		t.Fatalf("successful redemptions: %d", successes.Load())
	}
}

func TestSafeNextAllowsOnlyOpaqueLaunchContinuation(t *testing.T) {
	token, err := local.NewToken("", 32)
	if err != nil {
		t.Fatal(err)
	}
	next := launchContinuePath + "?token=" + token
	if got, ok := safeNextPath(next); !ok || got != next {
		t.Fatalf("local continuation rejected: %q %v", got, ok)
	}
	for _, unsafe := range []string{
		"/launch?url=https%3A%2F%2Fvendor.example", launchContinuePath,
		next + "&extra=x", next + "&token=" + token, next + "#fragment",
		launchContinuePath + "?token=short", "https://evil.example" + next,
	} {
		if _, ok := safeNextPath(unsafe); ok {
			t.Fatalf("unsafe return accepted: %q", unsafe)
		}
	}
}
