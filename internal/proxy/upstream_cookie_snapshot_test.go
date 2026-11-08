package proxy

import (
	"context"
	"errors"
	"net/url"
	"sync"
	"testing"

	"example.org/odo/internal/resources"
)

func TestUpstreamCookieSnapshotRetiresJarsAcrossSkippedReversion(t *testing.T) {
	f := newUpstreamCookieFixture(t)
	if err := f.m.ReplacePolicySnapshot(10, f.items); err != nil {
		t.Fatal(err)
	}
	var exchanges []*UpstreamCookieExchange
	var original []CookieAuthorization
	for _, resource := range []string{"a", "b"} {
		auth := f.auth(t, "alice", resource)
		_, exchange, err := prepareCookieRequest(t, f.m, "https://vendor.example/", cookieAuthorization(auth))
		if err != nil {
			t.Fatal(err)
		}
		if err := storeCookieResponse(t, exchange, "private=old"); err != nil {
			t.Fatal(err)
		}
		exchanges = append(exchanges, exchange)
		original = append(original, auth)
	}
	f.items[0].CookiePolicy.JarScope = " RESOURCE " // Same normalized policy.
	if err := f.m.ReplacePolicySnapshot(10, f.items); err != nil {
		t.Fatal(err)
	}
	for _, auth := range original {
		if current := f.auth(t, "alice", auth.ResourceID); current.PolicyGeneration != auth.PolicyGeneration {
			t.Fatal("unchanged revision renewed generations")
		}
		expectUpstreamCookies(t, f, auth, "https://vendor.example/", "private=old")
	}
	// Revision 11 changed a policy; 12 restored it before this consumer read it.
	// The final normalized policies alone cannot reveal that intervening change.
	if err := f.m.ReplacePolicySnapshot(12, f.items); err != nil {
		t.Fatal(err)
	}
	if len(f.m.jars) != 0 {
		t.Fatal("new revision retained old jars")
	}
	for i, old := range original {
		fresh := f.auth(t, "alice", old.ResourceID)
		if fresh.PolicyGeneration == old.PolicyGeneration || len(exchanges[i].jar.cookies) != 0 {
			t.Fatal("new revision reused old state")
		}
		if err := storeCookieResponse(t, exchanges[i], "late=old"); err == nil {
			t.Fatal("old exchange survived revision retirement")
		}
		if _, _, err := prepareCookieRequest(t, f.m, "https://vendor.example/", cookieAuthorization(old)); err == nil {
			t.Fatal("old generation still authorized")
		}
		expectUpstreamCookies(t, f, fresh, "https://vendor.example/", "")
	}
	// A delayed older snapshot and legacy installer cannot roll current state back.
	auth := f.auth(t, "alice", "a")
	_, exchange, err := prepareCookieRequest(t, f.m, "https://vendor.example/", cookieAuthorization(auth))
	if err != nil {
		t.Fatal(err)
	}
	if err := storeCookieResponse(t, exchange, "current=retained"); err != nil {
		t.Fatal(err)
	}
	if err := f.m.ReplacePolicySnapshot(11, f.items); !errors.Is(err, ErrCookiePolicy) {
		t.Fatal("older snapshot accepted")
	}
	if err := f.m.ReplacePolicies(f.items); !errors.Is(err, ErrCookiePolicy) {
		t.Fatal("legacy policy installation bypassed revision tracking")
	}
	expectUpstreamCookies(t, f, auth, "https://vendor.example/", "current=retained")
}

func TestUpstreamCookieSnapshotFailuresRetireAndPreventRollback(t *testing.T) {
	for _, kind := range []string{"unsupported", "inconsistent", "removed", "oversized", "overflow", "negative"} {
		t.Run(kind, func(t *testing.T) {
			f := newUpstreamCookieFixture(t)
			if err := f.m.ReplacePolicySnapshot(10, f.items); err != nil {
				t.Fatal(err)
			}
			auth := f.auth(t, "alice", "a")
			_, exchange, err := prepareCookieRequest(t, f.m, "https://vendor.example/", cookieAuthorization(auth))
			if err != nil {
				t.Fatal(err)
			}
			if err := storeCookieResponse(t, exchange, "private=old"); err != nil {
				t.Fatal(err)
			}
			items := append([]resources.Resource(nil), f.items...)
			revision := int64(11)
			switch kind {
			case "unsupported":
				items[0].CookiePolicy.JarScope = "parent"
			case "inconsistent":
				revision = 10
				items[0].CookiePolicy.Enabled = false
			case "removed":
				revision, items = 10, items[:1]
			case "oversized":
				items = make([]resources.Resource, UpstreamMaxPolicies+1)
			case "overflow":
				f.m.generation = ^uint64(0)
			case "negative":
				revision = -1
			}
			if err := f.m.ReplacePolicySnapshot(revision, items); err == nil || f.m.ready || len(f.m.jars) != 0 || len(f.m.policies) != 0 || len(exchange.jar.cookies) != 0 {
				t.Fatal("invalid snapshot retained usable state")
			}
			if err := storeCookieResponse(t, exchange, "late=old"); err == nil {
				t.Fatal("failed snapshot allowed old exchange")
			}
			floor := int64(10)
			if revision > floor {
				floor = revision
			}
			if err := f.m.ReplacePolicySnapshot(floor-1, f.items); err == nil || f.m.ready {
				t.Fatal("failed snapshot allowed revision rollback")
			}
			if err := f.m.ReplacePolicies(f.items); err == nil || f.m.ready {
				t.Fatal("failed snapshot allowed unversioned recovery")
			}
			if kind == "overflow" {
				if err := f.m.ReplacePolicySnapshot(12, f.items); err == nil {
					t.Fatal("exhausted generations recovered without restart")
				}
				return
			}
			if err := f.m.ReplacePolicySnapshot(12, f.items); err != nil {
				t.Fatal(err)
			}
			fresh := f.auth(t, "alice", "a")
			if fresh.PolicyGeneration == auth.PolicyGeneration {
				t.Fatal("recovery reused retired generation")
			}
			expectUpstreamCookies(t, f, fresh, "https://vendor.example/", "")
		})
	}
}

func TestUpstreamCookieSnapshotInitialFailureDisablesLegacyFallback(t *testing.T) {
	f := newUpstreamCookieFixture(t)
	if err := f.m.ReplacePolicySnapshot(-1, f.items); err == nil || f.m.ready {
		t.Fatal("invalid initial snapshot accepted")
	}
	if err := f.m.ReplacePolicies(f.items); err == nil || f.m.ready {
		t.Fatal("invalid initial snapshot allowed unversioned recovery")
	}
	if err := f.m.ReplacePolicySnapshot(0, f.items); err != nil {
		t.Fatal(err)
	}
}

func TestUpstreamCookieSnapshotConcurrentAccess(t *testing.T) {
	f := newUpstreamCookieFixture(t)
	if err := f.m.ReplacePolicySnapshot(0, f.items); err != nil {
		t.Fatal(err)
	}
	base := f.auth(t, "alice", "a")
	authorize := func(context.Context, *url.URL, string) (CookieAuthorization, error) {
		auth := base
		var err error
		auth.PolicyGeneration, err = f.m.PolicyGeneration(auth.ResourceID)
		return auth, err
	}
	var workers sync.WaitGroup
	for i := 0; i < 8; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for j := 0; j < 20; j++ {
				_, exchange, err := prepareCookieRequest(t, f.m, "https://vendor.example/", authorize)
				if err != nil {
					if !errors.Is(err, ErrCookieAuthorization) {
						t.Error(err)
					}
					continue
				}
				if err := storeCookieResponse(t, exchange, "private=current"); err != nil && !errors.Is(err, ErrCookieAuthorization) {
					t.Error(err)
				}
			}
		}()
	}
	for revision := int64(1); revision <= 20; revision++ {
		if err := f.m.ReplacePolicySnapshot(revision, f.items); err != nil {
			t.Fatal(err)
		}
	}
	workers.Wait()
	if err := f.m.ReplacePolicySnapshot(21, f.items); err != nil || len(f.m.jars) != 0 {
		t.Fatal("final revision retained old jars")
	}
}
