package api

import (
	"context"
	"database/sql"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"example.org/odo/internal/auth/local"
	"example.org/odo/internal/db"
	"example.org/odo/internal/proxy"
	"example.org/odo/internal/resources"
)

type securityFixture struct {
	h                                         *handoffSecurity
	control                                   *sql.DB
	central, authority, target, nonce, vendor string
	now                                       time.Time
}

func newSecurityFixture(t *testing.T) securityFixture {
	t.Helper()
	server, control, cookie, _ := newLogoutTestServer(t, true)
	server.ipLookup = publicTestResolver
	config, err := proxy.NewHostRoutingConfig("https://odo.example", "proxy.example")
	if err != nil {
		t.Fatal(err)
	}
	mapping, err := server.store.RegisterProxyHostname("vendor.example", "odo.example", "proxy.example")
	if err != nil {
		t.Fatal(err)
	}
	if err := server.store.UpsertResource(resources.Resource{ID: "vendor", Name: "Vendor", Domains: []resources.DomainRule{{Host: "vendor.example"}}}); err != nil {
		t.Fatal(err)
	}
	nonce, _ := local.NewToken("", 32)
	vendor, _ := local.NewToken("", 32)
	return securityFixture{h: &handoffSecurity{server: server, config: config, state: newPendingHandoffs()}, control: control, central: cookie.Value, authority: mapping.Label + ".proxy.example", target: "https://vendor.example/private?search=private-search", nonce: nonce, vendor: vendor, now: time.Now().UTC()}
}
func (f securityFixture) ticket(t *testing.T) string {
	t.Helper()
	pending, err := f.h.begin(context.Background(), f.central, f.authority, f.target, f.nonce, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.h.preflight(pending, f.authority, f.vendor, f.now); err != nil {
		t.Fatal(err)
	}
	if _, err = f.h.confirm(context.Background(), pending, "wrong-token", f.authority, f.nonce, f.now); err == nil {
		t.Fatal("wrong central credential confirmed")
	}
	ticket, err := f.h.confirm(context.Background(), pending, f.central, f.authority, f.nonce, f.now)
	if err != nil {
		t.Fatal(err)
	}
	return ticket
}
func (f securityFixture) grant(t *testing.T) string {
	t.Helper()
	ticket := f.ticket(t)
	grant, target, err := f.h.redeem(context.Background(), ticket, f.authority, f.vendor, f.now)
	if err != nil || target != f.target {
		t.Fatalf("redemption: %v", err)
	}
	if _, _, err = f.h.redeem(context.Background(), ticket, f.authority, f.vendor, f.now); err == nil {
		t.Fatal("replay accepted")
	}
	return grant
}
func TestHandoffSecurityLifecycle(t *testing.T) {
	f := newSecurityFixture(t)
	before, _, _ := f.h.server.store.GetSession(local.SessionIDFromToken(f.central))
	grant := f.grant(t)
	if err := f.h.validateGrant(context.Background(), grant, f.authority, f.target, "GET", f.now); err != nil {
		t.Fatal(err)
	}
	for _, check := range []struct {
		host, target, method string
		now                  time.Time
	}{
		{"unknown.proxy.example", f.target, "GET", f.now},
		{f.authority, "https://other.example/", "GET", f.now},
		{f.authority, f.target, "DELETE", f.now},
		{f.authority, f.target, "GET", f.now.Add(handoffGrantTTL)},
	} {
		if err := f.h.validateGrant(context.Background(), grant, check.host, check.target, check.method, check.now); err == nil {
			t.Fatal("invalid grant use accepted")
		}
	}
	after, _, _ := f.h.server.store.GetSession(before.ID)
	if before.LastSeenAt != after.LastSeenAt {
		t.Fatal("handoff touched session")
	}
}
func TestHandoffSecurityRevocation(t *testing.T) {
	mutations := map[string]func(securityFixture, string){
		"logout": func(f securityFixture, id string) {
			if err := f.h.server.store.RevokeSession(id); err != nil {
				t.Fatal(err)
			}
		},
		"password": func(f securityFixture, id string) {
			if _, err := f.h.server.store.SetUserPassword(id, "replacement-hash"); err != nil {
				t.Fatal(err)
			}
		},
		"disabled": func(f securityFixture, id string) {
			if _, _, err := f.h.server.store.SetUserStatus(id, "disabled"); err != nil {
				t.Fatal(err)
			}
		},
		"locked": func(f securityFixture, id string) {
			if _, _, err := f.h.server.store.SetUserStatus(id, "locked"); err != nil {
				t.Fatal(err)
			}
		},
		"deleted": func(f securityFixture, id string) {
			if _, err := f.h.server.store.DeleteUser(id, "administrator"); err != nil {
				t.Fatal(err)
			}
		},
		"roles": func(f securityFixture, id string) {
			if _, _, err := f.h.server.store.PatchUser(id, db.UserPatch{Roles: []string{"admin"}}); err != nil {
				t.Fatal(err)
			}
		},
		"epoch_only": func(f securityFixture, id string) {
			if _, err := f.control.Exec(`UPDATE users SET auth_version=auth_version+1 WHERE id=?`, id); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			f := newSecurityFixture(t)
			grant := f.grant(t)
			ticket := f.ticket(t)
			session, _, _ := f.h.server.store.GetSession(local.SessionIDFromToken(f.central))
			id := session.UserID
			if name == "logout" {
				id = session.ID
			}
			mutate(f, id)
			if err := f.h.validateGrant(context.Background(), grant, f.authority, f.target, "GET", f.now); err == nil {
				t.Fatal("revoked parent authorized grant")
			}
			if token, target, err := f.h.redeem(context.Background(), ticket, f.authority, f.vendor, f.now); err == nil || token != "" || target != "" {
				t.Fatal("revoked parent redeemed")
			}
			if len(f.h.state.grants) != 0 || len(f.h.state.tickets) != 0 {
				t.Fatal("invalid parent state not cleaned")
			}
		})
	}
}
func TestHandoffSecurityLivePolicy(t *testing.T) {
	for _, kind := range []string{"registry", "resource", "dns", "database"} {
		t.Run(kind, func(t *testing.T) {
			f := newSecurityFixture(t)
			grant := f.grant(t)
			ticket := f.ticket(t)
			switch kind {
			case "registry":
				if _, err := f.control.Exec(`DELETE FROM proxy_hostnames`); err != nil {
					t.Fatal(err)
				}
			case "resource":
				if err := f.h.server.store.UpsertResource(resources.Resource{ID: "vendor", Name: "Vendor", Status: "disabled", Domains: []resources.DomainRule{{Host: "vendor.example"}}}); err != nil {
					t.Fatal(err)
				}
			case "dns":
				f.h.server.ipLookup = func(context.Context, string) ([]net.IPAddr, error) {
					return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
				}
			case "database":
				if _, err := f.control.Exec(`ALTER TABLE sessions RENAME TO unavailable_sessions`); err != nil {
					t.Fatal(err)
				}
			}
			if err := f.h.validateGrant(context.Background(), grant, f.authority, f.target, "GET", f.now); err == nil {
				t.Fatal("stale authorization accepted")
			}
			if _, _, err := f.h.redeem(context.Background(), ticket, f.authority, f.vendor, f.now); err == nil {
				t.Fatal("stale authorization redeemed")
			}
			if _, err := f.h.begin(context.Background(), f.central, f.authority, f.target, f.nonce, f.now); err == nil {
				t.Fatal("unauthorized issuance")
			}
		})
	}
}
func TestHandoffSecurityConcurrentRedemption(t *testing.T) {
	f := newSecurityFixture(t)
	ticket := f.ticket(t)
	var successes atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, _, err := f.h.redeem(context.Background(), ticket, f.authority, f.vendor, f.now); err == nil {
				successes.Add(1)
			}
		}()
	}
	wg.Wait()
	if successes.Load() != 1 {
		t.Fatalf("successful redemptions: %d", successes.Load())
	}
}

func TestHandoffSecurityConfirmationRechecksPolicy(t *testing.T) {
	f := newSecurityFixture(t)
	pending, err := f.h.begin(context.Background(), f.central, f.authority, f.target, f.nonce, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.h.preflight(pending, f.authority, f.vendor, f.now); err != nil {
		t.Fatal(err)
	}
	if err := f.h.server.store.UpsertResource(resources.Resource{ID: "vendor", Name: "Vendor", Status: "disabled", Domains: []resources.DomainRule{{Host: "vendor.example"}}}); err != nil {
		t.Fatal(err)
	}
	if token, err := f.h.confirm(context.Background(), pending, f.central, f.authority, f.nonce, f.now); err == nil || token != "" {
		t.Fatal("changed policy confirmed")
	}
	if len(f.h.state.tickets) != 0 {
		t.Fatal("denied confirmation created ticket")
	}
}
