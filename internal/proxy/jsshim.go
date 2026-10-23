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
  var proxyURLMode = "` + ProxyURLMode() + `";
  var ownPrefix = proxyPrefix + "https/" + new URL(targetOrigin).host;
  function blockedScheme(value) {
    return /^(data|blob|mailto|tel|javascript):/i.test(String(value || ""));
  }
  function buildProxyURL(url) {
    var nestedPrefix = proxyPrefix + "https/" + url.host;
    if (url.protocol === "https:") {
      while (url.pathname === nestedPrefix || url.pathname.indexOf(nestedPrefix + "/") === 0) {
        url.pathname = url.pathname.slice(nestedPrefix.length) || "/";
      }
    }
    if (proxyURLMode === "query") {
      return "/odo?url=" + encodeURIComponent(url.href);
    }
    return proxyPrefix + "https/" + url.host + url.pathname + url.search + url.hash;
  }
  function currentTargetBase() {
    var current = new URL(window.location.href);
    if (current.pathname === ownPrefix || current.pathname.indexOf(ownPrefix + "/") === 0) {
      var path = current.pathname.slice(ownPrefix.length) || "/";
      return new URL(path + current.search + current.hash, targetOrigin).href;
    }
    if (current.pathname === "/odo" && current.searchParams.has("url")) {
      try {
        var target = new URL(current.searchParams.get("url"));
        if (target.origin === targetOrigin) return target.href;
      } catch (err) {}
    }
    return targetBase;
  }
  function rewriteURL(input) {
    if (input == null || blockedScheme(input)) return input;
    var raw = input instanceof URL ? input.href : String(input);
    var url;
    try { url = new URL(raw, currentTargetBase()); } catch (err) { return input; }
    if (url.origin !== window.location.origin && url.origin !== targetOrigin) return input;
    if (url.pathname === ownPrefix || url.pathname.indexOf(ownPrefix + "/") === 0) {
      url = new URL((url.pathname.slice(ownPrefix.length) || "/") + url.search + url.hash, targetOrigin);
    } else if (url.pathname.indexOf(proxyPrefix) === 0 || url.pathname === "/odo") {
      return input;
    } else if (url.origin === window.location.origin) {
      url = new URL(url.pathname + url.search + url.hash, targetOrigin);
    }
    if (url.origin !== targetOrigin) return input;
    return buildProxyURL(url);
  }
  // Vendor components create links after the server's HTML rewrite, including
  // inside shadow DOM. Keep native click, keyboard, and new-tab behavior.
  function rewriteLink(node) {
    if (!node || !node.matches || !node.matches("a[href], area[href]")) return;
    var href = node.getAttribute("href");
    if (!href || href.trim().charAt(0) === "#") return;
    var rewritten = rewriteURL(href);
    if (rewritten !== href) node.setAttribute("href", rewritten);
  }
  function rewriteLinks(root) {
    rewriteLink(root);
    if (root.querySelectorAll) root.querySelectorAll("a[href], area[href]").forEach(rewriteLink);
  }
  function prepareLink(event) {
    var path = event.composedPath();
    for (var i = 0; i < path.length; i++) {
      if (path[i].matches && path[i].matches("a[href], area[href]")) {
        rewriteLink(path[i]);
        break;
      }
    }
  }
  function watchLinks(root) {
    rewriteLinks(root);
    root.addEventListener("click", prepareLink, true);
    root.addEventListener("auxclick", prepareLink, true);
    var observer = new MutationObserver(function(records) {
      records.forEach(function(record) {
        if (record.type === "attributes") rewriteLink(record.target);
        record.addedNodes.forEach(rewriteLinks);
      });
    });
    observer.observe(root, {subtree: true, childList: true, attributes: true, attributeFilter: ["href"]});
  }
  watchLinks(document);
  if (Element.prototype.attachShadow) {
    var originalAttachShadow = Element.prototype.attachShadow;
    Element.prototype.attachShadow = function() {
      var root = originalAttachShadow.apply(this, arguments);
      watchLinks(root);
      return root;
    };
  }
  ["pushState", "replaceState"].forEach(function(method) {
    var original = history[method];
    history[method] = function(state, title, url) {
      if (arguments.length < 3 || url == null) return original.apply(this, arguments);
      return original.call(this, state, title, rewriteURL(url));
    };
  });
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
