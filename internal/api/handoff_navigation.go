package api

import (
	"net/http"
	"net/url"
	"strconv"
	"time"

	"example.org/odo/internal/auth/local"
	"example.org/odo/internal/db"
)

const handoffStartPath = "/launch/handoff/start"
const handoffAttemptCookie = "__Host-odo_handoff_attempt"

// Only this static script is allowed by the confirmation page's CSP hash.
// POST retains the existing CSRF, Origin, nonce and proof checks. Fetching the
// result before replacing the page also ends the login form's redirect chain:
// its form-action policy cannot accidentally govern later sibling-host hops.
const handoffContinueScript = `(() => {
 const status = document.getElementById("status");
 const fail = () => { status.textContent = "Unable to complete authentication. Allow cookies, then return to Resources and try again."; };
 let started = false;
 window.addEventListener("pageshow", async (event) => {
  if (event.persisted || started) { fail(); return; }
  started = true;
  const controller = new AbortController();
  const timeout = setTimeout(() => { controller.abort(); fail(); }, 15000);
  try {
   history.replaceState(null, "", location.pathname);
   const form = document.getElementById("handoff");
   const response = await fetch(form.action, {
    method: "POST", credentials: "same-origin", redirect: "error",
    headers: {"Accept": "application/json"},
    body: new URLSearchParams(new FormData(form)), signal: controller.signal
   });
   if (!response.ok) throw new Error("handoff failed");
   const result = await response.json();
   location.replace(result.next);
  } catch (_) { fail(); }
  finally { clearTimeout(timeout); }
 });
})();`

// This uses the existing bounded, expiring continuation store. An unbound
// start token carries only a destination, never authority to grant access; the
// full login/nonce/proof/CSRF protocol still follows. Empty-nonce records cannot
// be consumed by the browser-bound login continuation endpoint, or vice versa.
func (h *handoffSecurity) navigationStart(target string) (string, error) {
	token, err := h.server.launchContinuations.create(target, "", time.Now().UTC())
	if err != nil {
		return "", err
	}
	return (&url.URL{Scheme: "https", Host: h.config.CentralHostname(), Path: handoffStartPath, RawQuery: url.Values{"token": {token}}.Encode()}).String(), nil
}

func (h *handoffSecurity) resumeNavigation(w http.ResponseWriter, r *http.Request) {
	handoffHeaders(w, r, "handoff_start")
	if !requestOnCentralHost(r, h.config) || r.URL.EscapedPath() != handoffStartPath {
		writeError(w, http.StatusMisdirectedRequest, "request authority is not admitted")
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	token, valid := launchContinuationToken(r.URL.RawQuery)
	if !valid {
		handoffNavigationFailure(w, http.StatusNotFound)
		return
	}
	target, found := h.server.launchContinuations.consume(token, "", time.Now().UTC())
	if !found {
		handoffNavigationFailure(w, http.StatusNotFound)
		return
	}
	h.server.redirectLaunchTarget(w, r, target)
}

func handoffNavigationFailure(w http.ResponseWriter, status int) {
	writeError(w, status, "Authentication could not complete. Allow cookies and start again from Resources; an expired or repeated handoff cannot be reused.")
}

// Count failed returns on the exact vendor host, not successful launches. The
// counter is only a loop guard, never an authorization credential. Expiry lets
// a patron recover after changing browser cookie settings.
func beginHandoffAttempt(w http.ResponseWriter, r *http.Request) bool {
	count := 0
	if hasCookie(r, handoffAttemptCookie) {
		value, unique := uniqueConfirmationCookie(r, handoffAttemptCookie)
		parsed, err := strconv.Atoi(value)
		if !unique || err != nil || parsed < 0 || parsed >= 2 {
			handoffNavigationFailure(w, http.StatusLoopDetected)
			return false
		}
		count = parsed
	}
	http.SetCookie(w, handoffCookie(handoffAttemptCookie, strconv.Itoa(count+1), time.Now().Add(time.Minute)))
	return true
}

// Verify the newly set grant on a separate request before continuing. This
// makes a dropped grant cookie a terminal error instead of another handoff.
// The continuation is single-use and bound to that exact grant token.
func (h *handoffSecurity) verifyGrantRedirect(w http.ResponseWriter, r *http.Request, authority, grant, next string) {
	token, err := h.server.launchContinuations.create(next, grant, time.Now().UTC())
	if err != nil {
		h.server.internalError(w, r, err)
		return
	}
	location := url.URL{Scheme: "https", Host: authority, Path: handoffVendorPath, RawQuery: url.Values{"finish": {token}}.Encode()}
	w.Header().Set("Location", location.String())
	w.WriteHeader(http.StatusSeeOther)
}

func (h *handoffSecurity) finishNavigation(w http.ResponseWriter, r *http.Request, mapping db.ProxyHostname, authority, token string) {
	grant, unique := uniqueConfirmationCookie(r, vendorGrantCookie)
	if !unique {
		handoffNavigationFailure(w, http.StatusUnauthorized)
		return
	}
	live, _, err := h.grantParent(grant, authority, time.Now().UTC())
	if err != nil {
		handoffNavigationFailure(w, http.StatusUnauthorized)
		return
	}
	next, found := h.server.launchContinuations.consume(token, grant, time.Now().UTC())
	if !found {
		handoffNavigationFailure(w, http.StatusNotFound)
		return
	}
	destination, err := url.Parse(next)
	if err != nil || destination.Scheme != "https" || destination.User != nil {
		handoffNavigationFailure(w, http.StatusNotFound)
		return
	}
	if _, err := h.mapping(destination.Host); err != nil {
		handoffNavigationFailure(w, http.StatusForbidden)
		return
	}
	probe := (&url.URL{Scheme: "https", Host: mapping.Hostname, Path: "/"}).String()
	if destination.Host == authority && destination.Path != handoffVendorPath {
		upstream, ok := vendorUpstreamURL(mapping.Hostname, destination)
		if !ok {
			handoffNavigationFailure(w, http.StatusForbidden)
			return
		}
		probe = upstream.String()
	}
	if _, err := h.target(r.Context(), live.binding, probe, "GET", ""); err != nil {
		h.confirmationError(w, r, err)
		return
	}
	w.Header().Set("Location", next)
	w.WriteHeader(http.StatusSeeOther)
}

// discardPending is used only after a live grant for the same parent and exact
// target has been validated. The newly created handoff is then unnecessary.
func (h *handoffSecurity) discardPending(token string) {
	h.state.mu.Lock()
	delete(h.state.entries, local.HashToken(token))
	h.state.mu.Unlock()
}
