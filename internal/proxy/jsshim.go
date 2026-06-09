package proxy

import (
	"encoding/json"
	"os"
	"strings"
)

const jsShimMarker = `data-odo-js-shim="true"`

func InjectJSShimEnabled() bool {
	value := strings.ToLower(strings.TrimSpace(os.Getenv("APP_PROXY_INJECT_JS_SHIM")))
	switch value {
	case "", "true", "1", "yes", "on":
		return true
	case "false", "0", "no", "off":
		return false
	default:
		return true
	}
}

func InjectJSShim(html string, targetOrigin, targetBase string) (string, bool) {
	if strings.Contains(html, jsShimMarker) {
		return html, false
	}
	shim := BuildJSShim(targetOrigin, targetBase)
	lower := strings.ToLower(html)
	if idx := strings.Index(lower, "<head"); idx >= 0 {
		if end := strings.Index(html[idx:], ">"); end >= 0 {
			insertAt := idx + end + 1
			return html[:insertAt] + shim + html[insertAt:], true
		}
	}
	if idx := strings.Index(lower, "<body"); idx >= 0 {
		if end := strings.Index(html[idx:], ">"); end >= 0 {
			insertAt := idx + end + 1
			return html[:insertAt] + shim + html[insertAt:], true
		}
	}
	return shim + html, true
}

func BuildJSShim(targetOrigin, targetBase string) string {
	originJSON, _ := json.Marshal(targetOrigin)
	baseJSON, _ := json.Marshal(targetBase)
	return `<script ` + jsShimMarker + `>
(function(){
  "use strict";
  var targetOrigin = ` + string(originJSON) + `;
  var targetBase = ` + string(baseJSON) + `;
  var proxyPrefix = "/odo/";
  function blockedScheme(value) {
    return /^(data|blob|mailto|tel|javascript):/i.test(String(value || ""));
  }
  function buildProxyURL(url) {
    return "/odo/https/" + url.host + url.pathname + url.search + url.hash;
  }
  function rewriteURL(input) {
    if (input == null || blockedScheme(input)) return input;
    var raw = input instanceof URL ? input.href : String(input);
    if (raw.indexOf(proxyPrefix) === 0) return input;
    var url;
    try { url = new URL(raw, targetBase); } catch (err) { return input; }
    if (url.origin === window.location.origin) {
      if (url.pathname.indexOf(proxyPrefix) === 0 || url.pathname === "/odo") return input;
      url = new URL(url.pathname + url.search + url.hash, targetOrigin);
    }
    if (url.origin !== targetOrigin) return input;
    return buildProxyURL(url);
  }
  if (window.fetch) {
    var originalFetch = window.fetch;
    window.fetch = function(input, init) {
      var rewritten = rewriteURL(input instanceof Request ? input.url : input);
      if (input instanceof Request && rewritten !== input.url) {
        return originalFetch.call(this, new Request(rewritten, input), init);
      }
      return originalFetch.call(this, rewritten, init);
    };
  }
  if (window.XMLHttpRequest && window.XMLHttpRequest.prototype) {
    var originalOpen = window.XMLHttpRequest.prototype.open;
    window.XMLHttpRequest.prototype.open = function(method, url, async, username, password) {
      return originalOpen.call(this, method, rewriteURL(url), async, username, password);
    };
  }
  if (navigator.sendBeacon) {
    var originalSendBeacon = navigator.sendBeacon.bind(navigator);
    navigator.sendBeacon = function(url, data) {
      return originalSendBeacon(rewriteURL(url), data);
    };
  }
})();
</script>`
}
