package api

import (
	"context"
	"crypto/subtle"
	"errors"
	"time"

	"example.org/odo/internal/auth/local"
	"example.org/odo/internal/db"
	"example.org/odo/internal/proxy"
	"example.org/odo/internal/resources"
)

var errHandoffDenied = errors.New("handoff authorization denied")

// Internal coordinator only: deliberately not constructed by Server or exposed
// through HTTP. The passive store must never be used as an authorization cache.
type handoffSecurity struct {
	server *Server
	config proxy.HostRoutingConfig
	state  *pendingHandoffs
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

func (h *handoffSecurity) target(ctx context.Context, binding handoffBinding, raw, method string) error {
	mapping, err := h.mapping(binding.proxyAuthority)
	if err != nil {
		return err
	}
	if mapping.Hostname != binding.hostname || mapping.Label != binding.label {
		return errHandoffDenied
	}
	target, result := h.server.proxyTarget(ctx, raw)
	if result.InternalError != nil {
		return errors.New("handoff resource lookup failed")
	}
	if target == nil || target.Scheme != "https" || target.Hostname() != binding.hostname || !result.Allowed || !resources.MethodAllowed(result, method) {
		return errHandoffDenied
	}
	return nil
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
	if err = h.target(ctx, binding, target, "GET"); err != nil {
		return "", err
	}
	expires, _ := time.Parse(time.RFC3339, session.ExpiresAt)
	return h.state.create(binding, target, centralNonce, expires, now)
}

func (h *handoffSecurity) preflight(token, authority, nonce string, now time.Time) error {
	mapping, err := h.mapping(authority)
	if err != nil {
		return err
	}
	if !h.state.bindVendorNonce(token, mapping, authority, nonce, now) {
		return errHandoffDenied
	}
	return nil
}

func (h *handoffSecurity) confirm(ctx context.Context, token, centralToken, authority, nonce string, now time.Time) (string, error) {
	// Inspection uses a copied record, but confirmation still checks the complete
	// immutable binding under the state lock. No separate consume operation.
	h.state.mu.Lock()
	pending, found := h.state.entries[local.HashToken(token)]
	h.state.mu.Unlock()
	if !found || !validLaunchToken(token) || local.SessionIDFromToken(centralToken) != pending.binding.parentSessionID ||
		subtle.ConstantTimeCompare([]byte(h.server.browserSessionHash(centralToken)), []byte(pending.binding.parentSessionHash)) != 1 || authority != pending.binding.proxyAuthority {
		return "", errHandoffDenied
	}
	if _, err := h.parent(pending.binding, now); err != nil {
		return "", err
	}
	if err := h.target(ctx, pending.binding, pending.target, "GET"); err != nil {
		return "", err
	}
	return h.state.confirm(token, pending.binding, nonce, now)
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
	if err := h.target(ctx, ticket.binding, ticket.target, "GET"); err != nil {
		return "", "", err
	}
	return h.state.redeem(token, ticket.binding, nonce, now)
}

func (h *handoffSecurity) validateGrant(ctx context.Context, token, authority, target, method string, now time.Time) error {
	mapping, err := h.mapping(authority)
	if err != nil {
		return err
	}
	grant, found := h.state.inspectGrant(token, mapping, authority, now)
	if !found {
		return errHandoffDenied
	}
	if _, err := h.parent(grant.binding, now); err != nil {
		return err
	}
	return h.target(ctx, grant.binding, target, method)
}
