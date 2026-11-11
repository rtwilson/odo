package api

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"
	"time"

	"example.org/odo/internal/auth/local"
	"example.org/odo/internal/db"
	"example.org/odo/internal/proxy"
	"example.org/odo/internal/resources"
)

var errHandoffDenied = errors.New("handoff authorization denied")

// The experimental runtime constructs this coordinator for control routes and
// experimental vendor content delivery.
// The passive store must never be used as an authorization cache.
type handoffSecurity struct {
	server *Server
	config proxy.HostRoutingConfig
	state  *pendingHandoffs
	// Runtime-owned experimental vendor delivery. Both are constructed once with
	// the handoff runtime; never per request and never the legacy proxy store.
	cookies *grantCookieCoordinator
	vendor  *http.Client
}

func (h *handoffSecurity) mapping(authority string) (db.ProxyHostname, error) {
	central, label, err := h.config.ClassifyAuthority(authority)
	if err != nil || central || label == "" {
		return db.ProxyHostname{}, errHandoffDenied
	}
	mapping, found, err := h.server.store.LookupProxyHostname(label)
	if err != nil {
		return db.ProxyHostname{}, errors.New("handoff registry lookup failed")
	}
	if !found {
		return db.ProxyHostname{}, errHandoffDenied
	}
	host, expected, err := proxy.RegistryHostname(mapping.Hostname, h.config.CentralHostname(), h.config.ProxyBaseDomain())
	if err != nil || host != mapping.Hostname || expected != mapping.Label || authority != mapping.Label+"."+h.config.ProxyBaseDomain() {
		return db.ProxyHostname{}, errHandoffDenied
	}
	return mapping, nil
}

// parent checks one joined database snapshot, without touching last_seen_at.
// A revoked/expired parent or changed account epoch invalidates all its state.
func (h *handoffSecurity) parent(binding handoffBinding, now time.Time) (db.Session, error) {
	session, user, found, err := h.server.store.GetSessionWithUser(binding.parentSessionID)
	if err != nil {
		return db.Session{}, errors.New("handoff session lookup failed")
	}
	expires, expiryErr := time.Parse(time.RFC3339, session.ExpiresAt)
	seen, seenErr := time.Parse(time.RFC3339, session.LastSeenAt)
	if !found || session.RevokedAt != "" || user.Status != "active" || user.ID != binding.parentUserID || user.AuthVersion != binding.parentAuthVersion ||
		subtle.ConstantTimeCompare([]byte(session.SessionHash), []byte(binding.parentSessionHash)) != 1 || expiryErr != nil || seenErr != nil || !now.Before(expires) || now.Sub(seen) > sessionIdleTimeout() {
		h.state.removeParent(binding.parentSessionID, now)
		return db.Session{}, errHandoffDenied
	}
	return session, nil
}

func (h *handoffSecurity) target(ctx context.Context, binding handoffBinding, raw, method, resourceID string) (string, error) {
	mapping, err := h.mapping(binding.proxyAuthority)
	if err != nil {
		return "", err
	}
	if mapping.Hostname != binding.hostname || mapping.Label != binding.label {
		return "", errHandoffDenied
	}
	target, result := h.server.proxyTarget(ctx, raw)
	if result.InternalError != nil {
		return "", errors.New("handoff resource lookup failed")
	}
	if target == nil || target.Scheme != "https" || target.Hostname() != binding.hostname || !result.Allowed || !resources.MethodAllowed(result, method) || result.ResourceID == "" || (resourceID != "" && result.ResourceID != resourceID) {
		return "", errHandoffDenied
	}
	return result.ResourceID, nil
}

// begin accepts the complete central credential only in process memory. Later
// vendor operations use stored references, never central credentials in URLs.
func (h *handoffSecurity) begin(ctx context.Context, centralToken, authority, target, centralNonce string, now time.Time) (string, error) {
	id := local.SessionIDFromToken(centralToken)
	if id == "" {
		return "", errHandoffDenied
	}
	session, user, found, err := h.server.store.GetSessionWithUser(id)
	if err != nil {
		return "", errors.New("handoff session lookup failed")
	}
	hash := h.server.browserSessionHash(centralToken)
	if !found || subtle.ConstantTimeCompare([]byte(session.SessionHash), []byte(hash)) != 1 {
		return "", errHandoffDenied
	}
	mapping, err := h.mapping(authority)
	if err != nil {
		return "", err
	}
	binding := handoffBinding{parentSessionID: id, parentSessionHash: hash, parentUserID: user.ID, parentAuthVersion: user.AuthVersion, hostname: mapping.Hostname, label: mapping.Label, proxyAuthority: authority}
	if _, err = h.parent(binding, now); err != nil {
		return "", err
	}
	resourceID, err := h.target(ctx, binding, target, "GET", "")
	if err != nil {
		return "", err
	}
	expires, _ := time.Parse(time.RFC3339, session.ExpiresAt)
	return h.state.create(binding, target, resourceID, centralNonce, expires, now)
}

func (h *handoffSecurity) preflight(token, authority, nonce string, now time.Time) (string, error) {
	mapping, err := h.mapping(authority)
	if err != nil {
		return "", err
	}
	return h.state.prepare(token, mapping, authority, nonce, now)
}

// confirmation is a read-only authorization check for central rendering and
// POST. The state transition still repeats all immutable bindings under its lock.
func (h *handoffSecurity) confirmation(ctx context.Context, token, centralToken, nonce, proof string, now time.Time) (pendingHandoff, error) {
	if !validLaunchToken(token) || !validLaunchToken(nonce) {
		return pendingHandoff{}, errInvalidPendingHandoff
	}
	h.state.mu.Lock()
	pending, found := h.state.entries[local.HashToken(token)]
	h.state.mu.Unlock()
	if !found || !pending.acceptsReturnProof(proof, now) || pending.centralNonceHash != local.HashToken(nonce) || local.SessionIDFromToken(centralToken) != pending.binding.parentSessionID ||
		subtle.ConstantTimeCompare([]byte(h.server.browserSessionHash(centralToken)), []byte(pending.binding.parentSessionHash)) != 1 {
		return pendingHandoff{}, errInvalidPendingHandoff
	}
	if _, err := h.parent(pending.binding, now); err != nil {
		if errors.Is(err, errHandoffDenied) {
			return pendingHandoff{}, errInvalidPendingHandoff
		}
		return pendingHandoff{}, err
	}
	if _, err := h.target(ctx, pending.binding, pending.target, "GET", pending.resourceID); err != nil {
		return pendingHandoff{}, err
	}
	return pending, nil
}

func (h *handoffSecurity) confirm(ctx context.Context, token, centralToken, authority, nonce, proof string, now time.Time) (string, error) {
	pending, err := h.confirmation(ctx, token, centralToken, nonce, proof, now)
	if err != nil {
		return "", err
	}
	if authority != pending.binding.proxyAuthority {
		return "", errHandoffDenied
	}
	return h.state.confirm(token, pending.binding, nonce, proof, now)
}

func (h *handoffSecurity) redeem(ctx context.Context, token, authority, nonce string, now time.Time) (string, string, error) {
	mapping, err := h.mapping(authority)
	if err != nil {
		return "", "", err
	}
	ticket, found := h.state.inspectTicket(token, mapping, authority, nonce, now)
	if !found {
		return "", "", errHandoffDenied
	}
	if _, err := h.parent(ticket.binding, now); err != nil {
		return "", "", err
	}
	if _, err := h.target(ctx, ticket.binding, ticket.target, "GET", ticket.resourceID); err != nil {
		return "", "", err
	}
	return h.state.redeem(token, ticket.binding, nonce, now)
}

func (h *handoffSecurity) validateGrant(ctx context.Context, token, authority, target, method string, now time.Time) error {
	_, err := h.authorizeGrant(ctx, token, authority, target, method, now)
	return err
}

// grantAuthorization contains only the parent and winning-resource facts from
// one live grant check. It is not cached and cannot select a jar. The cookie
// coordinator reuses the parent checks with its guarded resource snapshot,
// rather than combining this independent lookup with a policy generation.
type grantAuthorization struct {
	parentSessionID   string
	parentSessionHash string
	parentExpires     time.Time
	resourceID        string
}

func (h *handoffSecurity) authorizeGrant(ctx context.Context, token, authority, target, method string, now time.Time) (grantAuthorization, error) {
	grant, parent, err := h.grantParent(token, authority, now)
	if err != nil {
		return grantAuthorization{}, err
	}
	resourceID, err := h.target(ctx, grant.binding, target, method, "")
	if err != nil {
		return grantAuthorization{}, err
	}
	return grantParentAuthorization(parent, resourceID, now)
}

// grantParent is shared by handoff validation and the internal cookie
// coordinator. A returned binding on parent failure is trusted server state,
// suitable for discarding cached cookies, never for granting access.
func (h *handoffSecurity) grantParent(token, authority string, now time.Time) (handoffGrant, db.Session, error) {
	mapping, err := h.mapping(authority)
	if err != nil {
		return handoffGrant{}, db.Session{}, err
	}
	grant, found := h.state.inspectGrant(token, mapping, authority, now)
	if !found {
		return handoffGrant{}, db.Session{}, errHandoffDenied
	}
	parent, err := h.parent(grant.binding, now)
	return grant, parent, err
}

func grantParentAuthorization(parent db.Session, resourceID string, now time.Time) (grantAuthorization, error) {
	// parent has already parsed and validated both timestamps. Do not extend
	// session activity or let a jar outlive the parent's idle/absolute deadline.
	expires, _ := time.Parse(time.RFC3339, parent.ExpiresAt)
	seen, _ := time.Parse(time.RFC3339, parent.LastSeenAt)
	if idle := seen.Add(sessionIdleTimeout()); idle.Before(expires) {
		expires = idle
	}
	if !now.Before(expires) {
		return grantAuthorization{}, errHandoffDenied
	}
	return grantAuthorization{parentSessionID: parent.ID, parentSessionHash: parent.SessionHash, parentExpires: expires, resourceID: resourceID}, nil
}
