package ui

func AdminHTML() string {
	return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>odo admin</title>
  <style>
    :root { color-scheme: dark; font-family: Inter, ui-sans-serif, system-ui, sans-serif; background: #101316; color: #f2f4f7; }
    body { margin: 0; }
    a { color: #8cc7ff; text-decoration: none; }
    a:hover { text-decoration: underline; }
    main { max-width: 1240px; margin: 0 auto; padding: 28px 20px 36px; }
    header { display: flex; align-items: center; justify-content: space-between; gap: 16px; border-bottom: 1px solid #2b3138; padding-bottom: 16px; }
    h1 { margin: 0; font-size: 28px; letter-spacing: 0; }
    h2 { margin: 0 0 14px; font-size: 20px; letter-spacing: 0; }
    h3 { margin: 18px 0 10px; font-size: 16px; letter-spacing: 0; }
    .muted { color: #aab3bd; }
    .topbar { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; margin-top: 18px; }
    .layout { display: grid; grid-template-columns: 210px minmax(0, 1fr); gap: 20px; margin-top: 22px; align-items: start; }
    nav { position: sticky; top: 16px; display: grid; gap: 8px; }
    .nav-button, button, input, textarea { border: 1px solid #39414b; background: #181d22; color: #f2f4f7; border-radius: 6px; padding: 10px 12px; font: inherit; }
    button, .nav-button { cursor: pointer; background: #245c45; border-color: #327957; }
    button:hover, .nav-button:hover { background: #2c704f; }
    .nav-button { text-align: left; background: #1d242a; border-color: #303943; }
    .nav-button.active { background: #2c704f; border-color: #3f946a; }
    button.danger { background: #6b2f35; border-color: #9b3f49; }
    button.danger:hover { background: #7d3840; }
    input { min-width: min(560px, 100%); }
    label { color: #c5d0db; }
    .field { display: inline-grid; gap: 4px; }
    textarea { width: 100%; min-height: 340px; box-sizing: border-box; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; line-height: 1.45; resize: vertical; }
    pre, .list, .table-wrap { overflow: auto; background: #181d22; border: 1px solid #2b3138; border-radius: 8px; padding: 12px; line-height: 1.45; }
    .card-list { display: grid; gap: 12px; }
    .resource-card { overflow-wrap: anywhere; background: #181d22; border: 1px solid #2b3138; border-radius: 8px; padding: 14px; }
    .resource-card.active { border-color: #5fb982; box-shadow: inset 4px 0 0 #5fb982; }
    .resource-card h4 { margin: 0 0 8px; font-size: 17px; letter-spacing: 0; }
    .resource-summary { display: grid; gap: 4px; margin: 0 0 10px; }
    .resource-summary div { overflow-wrap: anywhere; }
    .resource-actions { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 10px; }
    details { margin-top: 8px; }
    summary { cursor: pointer; color: #cfe4ff; }
    .section { display: none; }
    .section.active { display: block; }
    .toolbar { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; margin: 10px 0 16px; }
    .workspace { display: grid; grid-template-columns: 290px minmax(0, 1fr); gap: 18px; align-items: start; }
    .list { min-height: 340px; }
    .resource-item, .api-key-row, .user-row { display: block; width: 100%; text-align: left; margin-bottom: 8px; background: #1f262d; border-color: #303943; }
    .resource-item.active, .api-key-row.active, .user-row.active { background: #2c704f; border-color: #3f946a; }
    .sample { display: block; width: 100%; text-align: left; margin: 6px 0 10px; background: #222a32; border-color: #39424d; color: #cfe4ff; }
    table { width: 100%; border-collapse: collapse; }
    th, td { border-bottom: 1px solid #2b3138; padding: 8px; text-align: left; vertical-align: top; overflow-wrap: anywhere; }
    th { color: #c5d0db; font-weight: 600; }
    .output-title { margin-top: 22px; }
    @media (max-width: 860px) { .layout, .workspace { grid-template-columns: 1fr; } nav { position: static; grid-template-columns: repeat(2, minmax(0, 1fr)); } }
  </style>
</head>
<body>
  <main>
    <header>
      <h1>odo admin</h1>
      <span class="muted"><a href="/openapi.yaml">OpenAPI spec</a></span>
    </header>

    <section class="topbar" aria-label="Global admin controls">
      <input id="api-key" type="password" placeholder="Admin API Key" aria-label="Admin API Key">
      <span id="session-summary" class="muted">Loading current session...</span>
      <form method="post" action="/logout"><button>Logout</button></form>
      <span class="muted">Admin API Key is optional override mode and is used only in this page runtime.</span>
    </section>

    <div class="layout">
      <nav aria-label="Admin sections">
        <button class="nav-button active" data-section="dashboard">Dashboard</button>
        <button class="nav-button" data-section="resources" data-scopes="resources:read resources:write">Resources</button>
        <button class="nav-button" data-section="config" data-scopes="config:read config:write">Config</button>
        <button class="nav-button" data-section="diagnostics" data-scopes="diagnostics:read logs:read">Diagnostics / Logs</button>
        <button class="nav-button" data-section="api-keys" data-scopes="api_keys:read api_keys:write">API Keys</button>
        <button class="nav-button" data-section="users" data-scopes="users:read users:write">Users</button>
        <button class="nav-button" data-section="auth" data-scopes="auth:read auth:write">Auth / SAML</button>
        <button class="nav-button" data-section="settings" data-scopes="system:read">Settings / System</button>
      </nav>

      <div>
        <section id="section-dashboard" class="section active">
          <h2>Dashboard</h2>
          <div class="toolbar">
            <button id="dash-health">Health</button>
            <button id="dash-openapi">OpenAPI spec</button>
            <button id="dash-resources">Load Resources</button>
            <button id="dash-revisions">Load Config Revisions</button>
            <button id="dash-access-logs">Load Access Logs</button>
            <button id="dash-proxy-diagnostics">Load Proxy Diagnostics</button>
            <button id="dash-missed-rewrites">Load Missed Rewrites</button>
            <button id="dash-api-keys">Load API Keys</button>
            <button id="dash-users">Load Users</button>
          </div>
        </section>

        <section id="section-resources" class="section">
          <h2>Resources</h2>
          <div class="toolbar">
            <button id="load">Load Resources</button>
            <button id="new-resource">New Resource</button>
            <button id="save-resource">Save Resource</button>
            <button id="delete-resource" class="danger">Delete Resource</button>
            <button id="export-filtered-json">Export Filtered JSON</button>
          </div>
          <h3>Resource List</h3>
          <p class="muted">The built-in admin UI is intentionally simple. Advanced customization and automation should use the documented JSON APIs.</p>
          <div class="toolbar">
            <label class="field">Search resources<input id="resource-search" placeholder="Search title, ID, entry URL, domain, tag, or notes"></label>
            <label class="field">Status<select id="resource-status-filter"><option value="all">all statuses</option><option value="active">active</option><option value="disabled">disabled</option><option value="inactive">inactive</option></select></label>
            <label class="field">Rule type<select id="resource-behavior-filter"><option value="all">all rule types</option><option value="proxy">has proxy domains</option><option value="anonymous">has anonymous URL rules</option><option value="rewrite">has content rewrite rules</option><option value="headers">has request header rules</option><option value="cookies">has cookie policy</option></select></label>
            <label class="field">Complexity<select id="resource-complexity-filter"><option value="all">all complexity</option><option value="simple">simple</option><option value="advanced">advanced</option></select></label>
            <label class="field">Tag<select id="resource-tag-filter"><option value="all">all tags</option></select></label>
            <label class="field">Sort by<select id="resource-sort"><option value="title">title</option><option value="id">id</option><option value="status">status</option><option value="updated_at">updated_at</option><option value="domain_count">domain count</option><option value="complexity">complexity</option></select></label>
            <label class="field">Sort order<select id="resource-order"><option value="asc">asc</option><option value="desc">desc</option></select></label>
          </div>
          <div class="workspace">
            <aside><div id="resource-list" class="card-list">No resources loaded.</div></aside>
            <div>
              <div id="resource-detail" class="table-wrap">Select a resource to inspect domains, rules, compatibility, and actions.</div>
              <h3>Raw JSON Editor</h3>
              <textarea id="editor" spellcheck="false" aria-label="Resource JSON editor"></textarea>
            </div>
          </div>
          <h3>Proxy Test</h3>
          <div class="toolbar">
            <label class="field">Target URL<input id="url" value="https://www.jstor.org/stable/example"></label>
            <button id="test">Test Rule</button>
            <button id="open-proxy">Open Through Proxy</button>
            <button id="fetch-proxy">Fetch Through Proxy</button>
            <button id="resource-missed-rewrites">Load Missed Rewrites</button>
          </div>
          <p class="muted">Proxy Test shows matched resource ID, matched domain rule, behavior, role, allowed/denied decision, denial reason, proxy_url, and fetch status when available.</p>
          <div id="resource-test-output" class="table-wrap">Select a resource or enter a target URL to test proxy matching.</div>
          <h3>Resource Config Builder</h3>
          <p class="muted">Start with a title, entry URL, and main domain. Generate and validate JSON before saving. Add additional domains only when testing or diagnostics show they are needed. See docs/resource-how-to.md for the resource how-to guide.</p>
          <div class="toolbar">
            <label class="field">Resource ID<input id="builder-id" placeholder="jstor"></label>
            <label class="field">Title<input id="builder-title" placeholder="JSTOR"></label>
            <label class="field">Entry URL<input id="builder-entry-url" placeholder="https://www.jstor.org/"></label>
          </div>
          <div class="toolbar">
            <label><input type="checkbox" class="builder-method" value="GET" checked> GET</label>
            <label><input type="checkbox" class="builder-method" value="HEAD" checked> HEAD</label>
            <label><input type="checkbox" class="builder-method" value="POST" checked> POST</label>
            <label><input type="checkbox" class="builder-method" value="PUT"> PUT</label>
            <label><input type="checkbox" class="builder-method" value="PATCH"> PATCH</label>
            <label><input type="checkbox" class="builder-method" value="OPTIONS"> OPTIONS</label>
            <label><input type="checkbox" class="builder-method" value="DELETE"> DELETE</label>
          </div>
          <div class="toolbar">
            <label><input id="builder-cookie-enabled" type="checkbox" checked> Cookie policy enabled</label>
            <input id="builder-cookie-domains" placeholder="allowed cookie domains, comma-separated" aria-label="Allowed cookie domains">
          </div>
          <div id="builder-domains" class="list"></div>
          <div class="toolbar"><button id="add-domain">Add Domain</button></div>
          <h3>Anonymous URL Rules</h3>
          <div id="builder-anonymous-rules" class="list"></div>
          <div class="toolbar"><button id="add-anonymous-rule">Add Anonymous Rule</button></div>
          <div id="builder-headers" class="list"></div>
          <div class="toolbar"><button id="add-header-rule">Add Header Rule</button></div>
          <h3>Content Rewrite Rules</h3>
          <div id="builder-rewrite-rules" class="list"></div>
          <div class="toolbar"><button id="add-rewrite-rule">Add Rewrite Rule</button></div>
          <div class="toolbar">
            <label><input id="builder-referer-recovery" type="checkbox" checked> referer recovery</label>
            <label><input id="builder-js-shim" type="checkbox" checked> JS shim</label>
            <label><input id="builder-app-data" type="checkbox" checked> app data recovery</label>
          </div>
          <div class="toolbar">
            <button id="generate-json">Generate JSON</button>
            <button id="validate-json">Validate JSON</button>
            <button id="save-builder-resource">Save as Resource</button>
            <button id="export-json">Export JSON</button>
            <button id="load-existing-builder">Load Existing Resource into Builder</button>
          </div>
        </section>

        <section id="section-config" class="section">
          <h2>Config</h2>
          <div class="toolbar">
            <button id="validate">Validate Config</button>
            <button id="import">Import Config</button>
            <button id="revisions">Load Config Revisions</button>
          </div>
        </section>

        <section id="section-diagnostics" class="section">
          <h2>Diagnostics / Logs</h2>
          <div class="toolbar">
            <button id="access-logs">Load Access Logs</button>
            <button id="proxy-diagnostics">Load Proxy Diagnostics</button>
            <button id="missed-rewrites">Load Missed Rewrites</button>
          </div>
        </section>

        <section id="section-api-keys" class="section">
          <h2>API Keys</h2>
          <div class="toolbar">
            <button id="load-api-keys">Load API Keys</button>
            <button id="new-api-key">New API Key</button>
            <button id="create-api-key">Create API Key</button>
            <button id="rotate-api-key">Rotate Selected Key</button>
            <button id="revoke-api-key" class="danger">Revoke Selected Key</button>
            <button id="delete-api-key" class="danger">Delete Selected Key</button>
          </div>
          <div id="api-key-table" class="table-wrap">No API keys loaded.</div>
          <h3>API key JSON</h3>
          <textarea id="api-key-editor" spellcheck="false" aria-label="API key JSON editor"></textarea>
        </section>

        <section id="section-users" class="section">
          <h2>Users</h2>
          <div class="toolbar">
            <button id="load-users">Load Users</button>
            <button id="new-user">New User</button>
            <button id="create-user">Create User</button>
            <button id="update-user">Update User</button>
            <button id="set-user-password">Set Password</button>
            <button id="disable-user" class="danger">Disable</button>
            <button id="enable-user">Enable</button>
            <button id="lock-user" class="danger">Lock</button>
            <button id="unlock-user">Unlock</button>
            <button id="revoke-user-sessions" class="danger">Revoke Sessions</button>
          </div>
          <div class="workspace">
            <aside><div id="user-list" class="list">No users loaded.</div></aside>
            <div>
              <textarea id="user-editor" spellcheck="false" aria-label="User JSON editor"></textarea>
              <input id="user-password" type="password" placeholder="New user password" aria-label="New user password">
            </div>
          </div>
        </section>

        <section id="section-auth" class="section">
          <h2>Auth / SAML</h2>
          <p class="muted">Future SAML Service Provider configuration will live here.</p>
          <div class="toolbar">
            <button id="load-saml-providers">Load SAML Providers</button>
            <button id="new-saml-provider">New SAML Provider</button>
            <button id="save-saml-provider">Save SAML Provider</button>
            <button id="delete-saml-provider" class="danger">Delete SAML Provider</button>
            <button id="open-saml-metadata">Open SP Metadata</button>
          </div>
          <div id="saml-provider-list" class="list">No SAML providers loaded.</div>
          <h3>SAML provider JSON</h3>
          <textarea id="saml-editor" spellcheck="false" aria-label="SAML provider JSON editor"></textarea>
        </section>

        <section id="section-settings" class="section">
          <h2>Settings / System</h2>
          <div class="toolbar">
            <button id="settings-health">Health check</button>
            <button id="settings-system">Load System Info</button>
            <button id="settings-openapi">OpenAPI spec</button>
          </div>
          <p class="muted">Runtime configuration is controlled by environment variables. Secrets are not displayed here.</p>
          <div id="system-info" class="table-wrap">System information not loaded.</div>
        </section>

        <h3 class="output-title">Output</h3>
        <pre id="output">Ready.</pre>
      </div>
    </div>
  </main>

  <script>
    const output = document.querySelector('#output');
    const editor = document.querySelector('#editor');
    const apiKeyEditor = document.querySelector('#api-key-editor');
    const userEditor = document.querySelector('#user-editor');
    const samlEditor = document.querySelector('#saml-editor');
    const resourceList = document.querySelector('#resource-list');
    const resourceDetail = document.querySelector('#resource-detail');
    const resourceTestOutput = document.querySelector('#resource-test-output');
    const resourceSearch = document.querySelector('#resource-search');
    const resourceStatusFilter = document.querySelector('#resource-status-filter');
    const resourceBehaviorFilter = document.querySelector('#resource-behavior-filter');
    const resourceComplexityFilter = document.querySelector('#resource-complexity-filter');
    const resourceTagFilter = document.querySelector('#resource-tag-filter');
    const resourceSort = document.querySelector('#resource-sort');
    const resourceOrder = document.querySelector('#resource-order');
    const apiKeyTable = document.querySelector('#api-key-table');
    const userList = document.querySelector('#user-list');
    const samlProviderList = document.querySelector('#saml-provider-list');
    const systemInfo = document.querySelector('#system-info');
    const builderDomains = document.querySelector('#builder-domains');
    const builderHeaders = document.querySelector('#builder-headers');
    const builderAnonymousRules = document.querySelector('#builder-anonymous-rules');
    const builderRewriteRules = document.querySelector('#builder-rewrite-rules');
    let resources = [];
    let apiKeys = [];
    let users = [];
    let samlProviders = [];
    let selectedResourceId = '';
    let selectedAPIKeyId = '';
    let selectedUserId = '';
    let selectedSAMLProviderId = '';
    let currentSession = { authenticated: false, scopes: [] };

    const template = {
      id: 'new-resource',
      name: 'New Resource',
      status: 'active',
      description: '',
      tags: ['test'],
      domains: [
        { host: 'example.com', match: 'exact', role: 'content', action: 'proxy' }
      ],
      sample_urls: ['https://example.com/']
    };

    const apiKeyTemplate = {
      name: 'Local admin',
      scopes: ['admin'],
      expires_at: null
    };

    const userTemplate = {
      username: 'new-user',
      email: '',
      display_name: 'New User',
      password: '',
      roles: ['user'],
      status: 'active'
    };

    const samlProviderTemplate = {
      id: 'campus-shibboleth',
      name: 'Campus Shibboleth',
      status: 'active',
      entity_id: '',
      acs_url: '',
      sign_authn_requests: true,
      require_signed_assertions: true,
      require_signed_responses: true,
      attribute_mappings: {
        subject: 'urn:oid:0.9.2342.19200300.100.1.1',
        email: 'urn:oid:0.9.2342.19200300.100.1.3',
        affiliation: 'urn:oid:1.3.6.1.4.1.5923.1.1.1.1',
        entitlement: 'urn:oid:1.3.6.1.4.1.5923.1.1.1.7'
      },
      session_ttl_minutes: 480,
      idle_timeout_minutes: 60
    };

    const show = value => output.textContent = typeof value === 'string' ? value : JSON.stringify(value, null, 2);

    function addDomainRow(value = {}) {
      const row = document.createElement('div');
      row.className = 'toolbar';
      row.innerHTML = '<input class="domain-host" placeholder="host">' +
        '<select class="domain-behavior"><option>proxy</option><option>cookie_domain</option><option>redirect_only</option><option>block</option><option>external_allow</option></select>' +
        '<label><input type="checkbox" class="domain-subdomains"> include subdomains</label>' +
        '<select class="domain-role"><option>content</option><option>asset</option><option>api</option><option>auth</option><option>redirect</option><option>cookie</option><option>unknown</option></select>' +
        '<label><input type="checkbox" class="domain-rewrite-js"> rewrite_javascript</label>' +
        '<input class="domain-notes" placeholder="notes">' +
        '<button type="button" class="danger">Remove row</button>';
      row.querySelector('.domain-host').value = value.host || '';
      row.querySelector('.domain-behavior').value = value.behavior || 'proxy';
      row.querySelector('.domain-subdomains').checked = !!value.include_subdomains || value.match === 'subdomain';
      row.querySelector('.domain-role').value = value.role || 'content';
      row.querySelector('.domain-rewrite-js').checked = !!value.rewrite_javascript;
      row.querySelector('.domain-notes').value = value.notes || '';
      row.querySelector('button').addEventListener('click', () => row.remove());
      builderDomains.appendChild(row);
    }

    function addHeaderRuleRow(value = {}) {
      const row = document.createElement('div');
      row.className = 'toolbar';
      row.innerHTML = '<input class="header-name" placeholder="Header name">' +
        '<select class="header-action"><option>remove</option><option>preserve</option></select>' +
        '<select class="header-phase"><option>request</option><option>response</option></select>' +
        '<button type="button" class="danger">Remove row</button>';
      row.querySelector('.header-name').value = value.name || '';
      row.querySelector('.header-action').value = value.action || 'remove';
      row.querySelector('.header-phase').value = value.phase || 'request';
      row.querySelector('button').addEventListener('click', () => row.remove());
      builderHeaders.appendChild(row);
    }

    function addAnonymousRuleRow(value = {}) {
      const row = document.createElement('div');
      row.className = 'toolbar';
      row.innerHTML = '<input class="anon-pattern" placeholder="https://host/path/*">' +
        '<select class="anon-behavior"><option>allow_public_proxy</option><option>block</option></select>' +
        '<input class="anon-methods" placeholder="GET, HEAD">' +
        '<input class="anon-notes" placeholder="notes">' +
        '<button type="button" class="danger">Remove Rule</button>';
      row.querySelector('.anon-pattern').value = value.pattern || '';
      row.querySelector('.anon-behavior').value = value.behavior || 'allow_public_proxy';
      row.querySelector('.anon-methods').value = (value.methods || ['GET', 'HEAD']).join(', ');
      row.querySelector('.anon-notes').value = value.notes || '';
      row.querySelector('button').addEventListener('click', () => row.remove());
      builderAnonymousRules.appendChild(row);
    }

    function addRewriteRuleRow(value = {}) {
      const row = document.createElement('div');
      row.className = 'toolbar';
      row.innerHTML = '<input class="rewrite-types" placeholder="text/html, application/javascript">' +
        '<input class="rewrite-find" placeholder="Find">' +
        '<input class="rewrite-replace" placeholder="Replace">' +
        '<button type="button" class="danger">Remove Rule</button>';
      row.querySelector('.rewrite-types').value = (value.content_types || ['text/html']).join(', ');
      row.querySelector('.rewrite-find').value = value.find || '';
      row.querySelector('.rewrite-replace').value = value.replace || '';
      row.querySelector('button').addEventListener('click', () => row.remove());
      builderRewriteRules.appendChild(row);
    }

    function switchSection(name) {
      for (const section of document.querySelectorAll('.section')) section.classList.remove('active');
      for (const button of document.querySelectorAll('.nav-button')) button.classList.toggle('active', button.dataset.section === name);
      const target = document.querySelector('#section-' + name);
      if (target) target.classList.add('active');
    }

    for (const button of document.querySelectorAll('.nav-button')) {
      button.addEventListener('click', () => switchSection(button.dataset.section));
    }

    function adminHeaders(extra = {}, needsAuth = true) {
      const apiKey = document.querySelector('#api-key').value.trim();
      const method = (extra['X-Odo-Method'] || '').toUpperCase();
      const unsafe = ['POST', 'PUT', 'PATCH', 'DELETE'].includes(method);
      const csrf = document.cookie.split('; ').find(row => row.startsWith('odo_csrf='));
      return {
        'Content-Type': 'application/json',
        ...(needsAuth && apiKey ? { 'Authorization': 'Bearer ' + apiKey } : {}),
        ...(needsAuth && !apiKey && unsafe && csrf ? { 'X-Odo-CSRF': decodeURIComponent(csrf.split('=')[1]) } : {}),
        ...extra
      };
    }

    async function api(path, options = {}) {
      const method = options.method || 'GET';
      const needsAuth = options.auth !== false;
      const extraHeaders = { ...(options.headers || {}), 'X-Odo-Method': method };
      const headers = adminHeaders(extraHeaders, needsAuth);
      delete headers['X-Odo-Method'];
      const response = await fetch(path, { ...options, method, headers });
      const text = await response.text();
      let body = text;
      try { body = text ? JSON.parse(text) : null; } catch (_) {}
      const result = { method, url: path, status: response.status, ok: response.ok, body };
      if (!response.ok) throw result;
      return result;
    }

    function unwrap(result) {
      return result && Object.prototype.hasOwnProperty.call(result, 'body') ? result.body : result;
    }

    function hasScope(scope) {
      const scopes = currentSession.scopes || [];
      return scopes.includes('admin') || scopes.includes(scope);
    }

    function hasAnyScope(scopesText) {
      if (!scopesText) return true;
      return scopesText.split(/\s+/).filter(Boolean).some(hasScope);
    }

    function applyPermissions() {
      for (const button of document.querySelectorAll('.nav-button[data-scopes]')) {
        button.hidden = !hasAnyScope(button.dataset.scopes);
      }
      const canWriteResources = hasScope('resources:write');
      for (const id of ['new-resource', 'save-resource', 'delete-resource', 'save-builder-resource']) {
        const el = document.querySelector('#' + id);
        if (el) el.disabled = !canWriteResources;
      }
      document.querySelector('#session-summary').textContent = currentSession.authenticated
        ? ((currentSession.display_name || currentSession.username || currentSession.name || currentSession.subject_type) + ' | roles: ' + (currentSession.roles || []).join(', ') + ' | scopes: ' + (currentSession.scopes || []).join(', '))
        : 'Not signed in';
    }

    async function loadSession() {
      try {
        const result = await api('/api/v1/session/me', { auth: false });
        currentSession = unwrap(result) || { authenticated: false, scopes: [] };
        applyPermissions();
      } catch (err) {
        currentSession = { authenticated: false, scopes: [] };
        applyPermissions();
      }
    }

    function proxyURL(raw) {
      return '/odo?url=' + encodeURIComponent(new URL(raw).href);
    }

    function summarizeMissedRewrites(data) {
      const summary = {};
      for (const event of data.events || []) {
        const key = [
          event.recovered_target_host || 'unknown-host',
          event.request_kind || 'unknown',
          event.recovery_action || 'not_recovered',
          event.upstream_status || 0
        ].join(' | ');
        summary[key] = (summary[key] || 0) + 1;
      }
      return { summary, events: data.events || [] };
    }

    function setEditor(value) {
      editor.value = JSON.stringify(value, null, 2);
      selectedResourceId = value.id || '';
      const entry = firstEntryURL(value);
      if (entry) document.querySelector('#url').value = entry;
      renderResourceDetail(value);
      renderResources();
    }

    function selectedResource() {
      return resources.find(resource => resource.id === selectedResourceId) || null;
    }

    function firstEntryURL(resource) {
      return ((resource || {}).entry_urls || (resource || {}).sample_urls || [''])[0] || '';
    }

    function resourceTitle(resource) {
      return resource.title || resource.name || resource.id || '';
    }

    function domainBehavior(domain) {
      return domain.behavior || domain.action || (domain.role === 'blocked' ? 'block' : 'proxy');
    }

    function resourceComplexity(resource) {
      const methods = resource.http_methods || ['GET', 'HEAD', 'POST'];
      const behaviors = new Set((resource.domains || []).map(domainBehavior));
      const basicHeaderRules = (resource.request_header_rules || []).filter(rule => rule.name !== 'X-Requested-With' || rule.action !== 'remove');
      const advanced = (resource.anonymous_url_rules || []).length ||
        (resource.content_rewrite_rules || []).length ||
        basicHeaderRules.length ||
        (resource.domains || []).length > 2 ||
        behaviors.size > 1 ||
        methods.some(method => !['GET', 'HEAD', 'POST'].includes(method));
      return advanced ? 'advanced' : 'simple';
    }

    function resourceSearchText(resource) {
      return [
        resourceTitle(resource),
        resource.id,
        ...(resource.entry_urls || []),
        ...((resource.domains || []).map(domain => [domain.host, domain.notes, domain.role, domain.behavior].join(' '))),
        ...(resource.tags || []),
        resource.description || ''
      ].join(' ').toLowerCase();
    }

    function filteredResources() {
      const search = resourceSearch.value.trim().toLowerCase();
      const status = resourceStatusFilter.value;
      const behavior = resourceBehaviorFilter.value;
      const complexity = resourceComplexityFilter.value;
      const tag = resourceTagFilter.value;
      let items = resources.filter(resource => {
        if (search && !resourceSearchText(resource).includes(search)) return false;
        if (status !== 'all' && (resource.status || 'active') !== status) return false;
        if (tag !== 'all' && !(resource.tags || []).includes(tag)) return false;
        if (complexity !== 'all' && resourceComplexity(resource) !== complexity) return false;
        if (behavior === 'proxy' && !(resource.domains || []).some(domain => domainBehavior(domain) === 'proxy')) return false;
        if (behavior === 'anonymous' && !(resource.anonymous_url_rules || []).length) return false;
        if (behavior === 'rewrite' && !(resource.content_rewrite_rules || []).length) return false;
        if (behavior === 'headers' && !(resource.request_header_rules || []).length) return false;
        if (behavior === 'cookies' && !(resource.cookie_policy || {}).enabled) return false;
        return true;
      });
      const sort = resourceSort.value;
      const dir = resourceOrder.value === 'desc' ? -1 : 1;
      items = items.slice().sort((a, b) => {
        const av = sort === 'title' ? resourceTitle(a).toLowerCase() :
          sort === 'id' ? (a.id || '') :
          sort === 'status' ? (a.status || 'active') :
          sort === 'updated_at' ? (a.updated_at || '') :
          sort === 'domain_count' ? (a.domains || []).length :
          resourceComplexity(a);
        const bv = sort === 'title' ? resourceTitle(b).toLowerCase() :
          sort === 'id' ? (b.id || '') :
          sort === 'status' ? (b.status || 'active') :
          sort === 'updated_at' ? (b.updated_at || '') :
          sort === 'domain_count' ? (b.domains || []).length :
          resourceComplexity(b);
        return av < bv ? -1 * dir : av > bv ? 1 * dir : 0;
      });
      return items;
    }

    function refreshTagFilter() {
      const current = resourceTagFilter.value;
      const tags = Array.from(new Set(resources.flatMap(resource => resource.tags || []))).sort();
      resourceTagFilter.textContent = '';
      const all = document.createElement('option');
      all.value = 'all';
      all.textContent = 'all tags';
      resourceTagFilter.appendChild(all);
      for (const tag of tags) {
        const option = document.createElement('option');
        option.value = tag;
        option.textContent = tag;
        resourceTagFilter.appendChild(option);
      }
      resourceTagFilter.value = tags.includes(current) ? current : 'all';
    }

    function summarizeList(items, emptyText) {
      return items && items.length ? items.join(', ') : emptyText;
    }

    function renderResourceDetail(resource) {
      if (!resource) {
        resourceDetail.textContent = 'Select a resource to inspect domains, rules, compatibility, and actions.';
        return;
      }
      const groups = {};
      for (const domain of resource.domains || []) {
        const behavior = domainBehavior(domain);
        groups[behavior] = groups[behavior] || [];
        groups[behavior].push(domain.host + (domain.include_subdomains || domain.match === 'subdomain' ? ' + subdomains' : '') + (domain.role ? ' (' + domain.role + ')' : ''));
      }
      const table = document.createElement('table');
      const rows = [
        ['title', resourceTitle(resource)],
        ['id', resource.id || ''],
        ['status', resource.status || 'active'],
        ['tags', summarizeList(resource.tags || [], 'none')],
        ['entry URLs', summarizeList(resource.entry_urls || resource.sample_urls || [], 'none')],
        ['domains by behavior', Object.entries(groups).map(([key, value]) => key + ': ' + value.join(', ')).join(' | ') || 'none'],
        ['HTTP methods', summarizeList(resource.http_methods || ['GET', 'HEAD', 'POST'], 'default')],
        ['cookie policy', (resource.cookie_policy || {}).enabled ? 'enabled; domains: ' + summarizeList((resource.cookie_policy || {}).allowed_cookie_domains || [], 'resource') : 'disabled'],
        ['request header rules', String((resource.request_header_rules || []).length)],
        ['anonymous URL rules', String((resource.anonymous_url_rules || []).length)],
        ['content rewrite rules', String((resource.content_rewrite_rules || []).length)],
        ['compatibility flags', JSON.stringify(resource.compatibility || {})],
        ['complexity', resourceComplexity(resource)]
      ];
      for (const [label, value] of rows) {
        const tr = document.createElement('tr');
        const th = document.createElement('th');
        const td = document.createElement('td');
        th.textContent = label;
        td.textContent = value;
        tr.appendChild(th);
        tr.appendChild(td);
        table.appendChild(tr);
      }
      const actions = document.createElement('div');
      actions.className = 'toolbar';
      actions.innerHTML = '<button id="detail-open">Open first entry URL through proxy</button><button id="detail-test">Test first entry URL</button><button id="detail-validate">Validate resource</button><button id="detail-load-builder">Load into Builder</button><button id="detail-edit-json">Edit raw JSON</button><button id="detail-export">Export JSON</button>';
      resourceDetail.textContent = '';
      resourceDetail.appendChild(table);
      resourceDetail.appendChild(actions);
      actions.querySelector('#detail-open').addEventListener('click', () => { const entry = firstEntryURL(resource); if (entry) window.open(proxyURL(entry), '_blank', 'noopener'); });
      actions.querySelector('#detail-test').addEventListener('click', async () => { const entry = firstEntryURL(resource); if (entry) { document.querySelector('#url').value = entry; await testRule(); } });
      actions.querySelector('#detail-validate').addEventListener('click', async () => validateResource(resource));
      actions.querySelector('#detail-load-builder').addEventListener('click', () => { loadBuilder(resource); show('Resource loaded into builder.'); });
      actions.querySelector('#detail-edit-json').addEventListener('click', () => setEditor(resource));
      actions.querySelector('#detail-export').addEventListener('click', () => downloadJSON('resource-' + (resource.id || 'selected') + '.json', resource));
    }

    function buildResourceConfig() {
      const methods = Array.from(document.querySelectorAll('.builder-method:checked')).map(input => input.value);
      const domains = Array.from(builderDomains.querySelectorAll('.toolbar')).map(row => ({
        host: row.querySelector('.domain-host').value.trim(),
        behavior: row.querySelector('.domain-behavior').value,
        include_subdomains: row.querySelector('.domain-subdomains').checked,
        role: row.querySelector('.domain-role').value,
        rewrite_javascript: row.querySelector('.domain-rewrite-js').checked,
        notes: row.querySelector('.domain-notes').value.trim()
      })).filter(domain => domain.host);
      const requestHeaderRules = Array.from(builderHeaders.querySelectorAll('.toolbar')).map(row => ({
        name: row.querySelector('.header-name').value.trim(),
        action: row.querySelector('.header-action').value,
        phase: row.querySelector('.header-phase').value
      })).filter(rule => rule.name);
      const anonymousRules = Array.from(builderAnonymousRules.querySelectorAll('.toolbar')).map(row => ({
        pattern: row.querySelector('.anon-pattern').value.trim(),
        behavior: row.querySelector('.anon-behavior').value,
        methods: row.querySelector('.anon-methods').value.split(',').map(value => value.trim()).filter(Boolean),
        notes: row.querySelector('.anon-notes').value.trim()
      })).filter(rule => rule.pattern);
      const rewriteRules = Array.from(builderRewriteRules.querySelectorAll('.toolbar')).map(row => ({
        content_types: row.querySelector('.rewrite-types').value.split(',').map(value => value.trim()).filter(Boolean),
        find: row.querySelector('.rewrite-find').value,
        replace: row.querySelector('.rewrite-replace').value
      })).filter(rule => rule.find);
      const entryURL = document.querySelector('#builder-entry-url').value.trim();
      const cookieDomains = document.querySelector('#builder-cookie-domains').value.split(',').map(value => value.trim()).filter(Boolean);
      return {
        id: document.querySelector('#builder-id').value.trim(),
        title: document.querySelector('#builder-title').value.trim(),
        status: 'active',
        tags: [],
        entry_urls: entryURL ? [entryURL] : [],
        http_methods: methods,
        cookie_policy: {
          enabled: document.querySelector('#builder-cookie-enabled').checked,
          jar_scope: 'resource',
          allowed_cookie_domains: cookieDomains
        },
        request_header_rules: requestHeaderRules,
        anonymous_url_rules: anonymousRules,
        content_rewrite_rules: rewriteRules,
        domains,
        compatibility: {
          referer_recovery: document.querySelector('#builder-referer-recovery').checked,
          js_shim: document.querySelector('#builder-js-shim').checked,
          app_data_recovery: document.querySelector('#builder-app-data').checked,
          javascript_text_rewriting: domains.some(domain => domain.rewrite_javascript)
        }
      };
    }

    function loadBuilder(resource) {
      document.querySelector('#builder-id').value = resource.id || '';
      document.querySelector('#builder-title').value = resource.title || resource.name || '';
      document.querySelector('#builder-entry-url').value = (resource.entry_urls || resource.sample_urls || [''])[0] || '';
      const methods = new Set(resource.http_methods || ['GET', 'HEAD', 'POST']);
      for (const input of document.querySelectorAll('.builder-method')) input.checked = methods.has(input.value);
      document.querySelector('#builder-cookie-enabled').checked = !!(resource.cookie_policy || {}).enabled;
      document.querySelector('#builder-cookie-domains').value = ((resource.cookie_policy || {}).allowed_cookie_domains || []).join(', ');
      builderDomains.textContent = '';
      for (const domain of resource.domains || []) addDomainRow(domain);
      builderHeaders.textContent = '';
      for (const rule of resource.request_header_rules || []) addHeaderRuleRow(rule);
      builderAnonymousRules.textContent = '';
      for (const rule of resource.anonymous_url_rules || []) addAnonymousRuleRow(rule);
      builderRewriteRules.textContent = '';
      for (const rule of resource.content_rewrite_rules || []) addRewriteRuleRow(rule);
      if (!builderDomains.children.length) addDomainRow();
      const compatibility = resource.compatibility || {};
      document.querySelector('#builder-referer-recovery').checked = compatibility.referer_recovery !== false;
      document.querySelector('#builder-js-shim').checked = compatibility.js_shim !== false;
      document.querySelector('#builder-app-data').checked = compatibility.app_data_recovery !== false;
    }

    function parseJSONEditor(textarea, label) {
      try {
        return JSON.parse(textarea.value);
      } catch (err) {
        show({ error: label + ' JSON is invalid', detail: err.message });
        return null;
      }
    }

    function renderResources() {
      refreshTagFilter();
      const items = filteredResources();
      if (!resources.length) {
        resourceList.textContent = 'No resources loaded.';
        return;
      }
      if (!items.length) {
        resourceList.textContent = 'No resources match the current search and filters.';
        return;
      }
      resourceList.textContent = '';
      for (const resource of items) {
        const card = document.createElement('article');
        card.className = 'resource-card' + (resource.id === selectedResourceId ? ' active' : '');
        const title = document.createElement('h4');
        title.textContent = resourceTitle(resource) || 'Untitled resource';
        const summary = document.createElement('div');
        summary.className = 'resource-summary';
        const addSummary = (label, value) => {
          const item = document.createElement('div');
          const strong = document.createElement('strong');
          strong.textContent = label + ': ';
          item.appendChild(strong);
          item.appendChild(document.createTextNode(value || 'none'));
          summary.appendChild(item);
        };
        addSummary('ID', resource.id || '');
        addSummary('Status', resource.status || 'active');
        addSummary('Entry URL', firstEntryURL(resource));
        addSummary('Main domains', (resource.domains || []).slice(0, 3).map(domain => domain.host).join(', '));
        addSummary('Tags', (resource.tags || []).join(', '));
        addSummary('Complexity', resourceComplexity(resource));
        const details = document.createElement('details');
        const detailsSummary = document.createElement('summary');
        detailsSummary.textContent = 'Details';
        const detailList = document.createElement('div');
        detailList.className = 'resource-summary';
        const addDetail = (label, value) => {
          const item = document.createElement('div');
          const strong = document.createElement('strong');
          strong.textContent = label + ': ';
          item.appendChild(strong);
          item.appendChild(document.createTextNode(value || 'none'));
          detailList.appendChild(item);
        };
        addDetail('All domains', (resource.domains || []).map(domain => domain.host + ' (' + domainBehavior(domain) + ')').join(', '));
        addDetail('Updated at', resource.updated_at || '');
        addDetail('HTTP methods', summarizeList(resource.http_methods || ['GET', 'HEAD', 'POST'], 'default'));
        addDetail('Request header rules', String((resource.request_header_rules || []).length));
        addDetail('Anonymous URL rules', String((resource.anonymous_url_rules || []).length));
        addDetail('Content rewrite rules', String((resource.content_rewrite_rules || []).length));
        details.appendChild(detailsSummary);
        details.appendChild(detailList);
        const actions = document.createElement('div');
        actions.className = 'resource-actions';
        const select = document.createElement('button');
        select.textContent = 'Select';
        select.addEventListener('click', () => setEditor(resource));
        const edit = document.createElement('button');
        edit.textContent = 'Edit JSON';
        edit.addEventListener('click', () => setEditor(resource));
        const builder = document.createElement('button');
        builder.textContent = 'Load into Builder';
        builder.addEventListener('click', () => { setEditor(resource); loadBuilder(resource); show('Resource loaded into builder.'); });
        const validate = document.createElement('button');
        validate.textContent = 'Validate';
        validate.addEventListener('click', () => validateResource(resource));
        const test = document.createElement('button');
        test.textContent = 'Test';
        test.addEventListener('click', async () => { setEditor(resource); const entry = firstEntryURL(resource); if (entry) document.querySelector('#url').value = entry; await testRule(); });
        const open = document.createElement('button');
        open.textContent = 'Open';
        open.addEventListener('click', () => { const entry = firstEntryURL(resource); if (entry) window.open(proxyURL(entry), '_blank', 'noopener'); });
        const exportButton = document.createElement('button');
        exportButton.textContent = 'Export';
        exportButton.addEventListener('click', () => downloadJSON('resource-' + (resource.id || 'selected') + '.json', resource));
        const del = document.createElement('button');
        del.textContent = 'Delete';
        del.className = 'danger';
        del.disabled = !hasScope('resources:write');
        del.addEventListener('click', async () => { setEditor(resource); document.querySelector('#delete-resource').click(); });
        for (const button of [select, edit, builder, validate, test, open, exportButton, del]) actions.appendChild(button);
        card.appendChild(title);
        card.appendChild(summary);
        card.appendChild(details);
        card.appendChild(actions);
        resourceList.appendChild(card);
      }
      if (!selectedResourceId && items[0]) setEditor(items[0]);
    }

    function selectAPIKey(key) {
      selectedAPIKeyId = key.id || '';
      apiKeyEditor.value = JSON.stringify({
        id: key.id,
        name: key.name,
        scopes: key.scopes || [],
        expires_at: key.expires_at || null
      }, null, 2);
      renderAPIKeys();
    }

    function renderAPIKeys() {
      if (!apiKeys.length) {
        apiKeyTable.textContent = 'No API keys loaded.';
        return;
      }
      const columns = ['id', 'name', 'key_prefix', 'scopes', 'status', 'expires_at', 'created_at', 'last_used_at', 'revoked_at'];
      const table = document.createElement('table');
      const thead = document.createElement('thead');
      const headRow = document.createElement('tr');
      for (const column of ['select', ...columns]) {
        const th = document.createElement('th');
        th.textContent = column;
        headRow.appendChild(th);
      }
      thead.appendChild(headRow);
      table.appendChild(thead);
      const tbody = document.createElement('tbody');
      for (const key of apiKeys) {
        const row = document.createElement('tr');
        const selectCell = document.createElement('td');
        const select = document.createElement('button');
        select.className = 'api-key-row' + (key.id === selectedAPIKeyId ? ' active' : '');
        select.textContent = key.id === selectedAPIKeyId ? 'Selected' : 'Select';
        select.addEventListener('click', () => selectAPIKey(key));
        selectCell.appendChild(select);
        row.appendChild(selectCell);
        for (const column of columns) {
          const td = document.createElement('td');
          const value = column === 'scopes' ? (key.scopes || []).join(', ') : (key[column] || '');
          td.textContent = value;
          row.appendChild(td);
        }
        tbody.appendChild(row);
      }
      table.appendChild(tbody);
      apiKeyTable.textContent = '';
      apiKeyTable.appendChild(table);
    }

    function selectUser(user) {
      selectedUserId = user.id || '';
      userEditor.value = JSON.stringify({
        id: user.id,
        username: user.username,
        email: user.email || '',
        display_name: user.display_name || '',
        roles: user.roles || [],
        status: user.status || 'active',
        created_at: user.created_at || '',
        updated_at: user.updated_at || '',
        last_login_at: user.last_login_at || '',
        locked_at: user.locked_at || '',
        disabled_at: user.disabled_at || ''
      }, null, 2);
      renderUsers();
    }

    function renderUsers() {
      if (!users.length) {
        userList.textContent = 'No users loaded.';
        return;
      }
      userList.textContent = '';
      for (const user of users) {
        const button = document.createElement('button');
        button.className = 'user-row' + (user.id === selectedUserId ? ' active' : '');
        button.textContent = user.username + ' - ' + user.status + ' - ' + (user.roles || []).join(', ');
        button.addEventListener('click', () => selectUser(user));
        userList.appendChild(button);
      }
    }

    function setSAMLEditor(provider) {
      selectedSAMLProviderId = provider.id || '';
      samlEditor.value = JSON.stringify(provider, null, 2);
      renderSAMLProviders();
    }

    function renderSAMLProviders() {
      if (!samlProviders.length) {
        samlProviderList.textContent = 'No SAML providers loaded.';
        return;
      }
      samlProviderList.textContent = '';
      for (const provider of samlProviders) {
        const button = document.createElement('button');
        button.className = 'resource-item' + (provider.id === selectedSAMLProviderId ? ' active' : '');
        button.textContent = provider.id + ' - ' + provider.name + ' (' + provider.status + ')';
        button.addEventListener('click', () => setSAMLEditor(provider));
        samlProviderList.appendChild(button);
      }
    }

    function renderSystemInfo(data) {
      const columns = ['app_env', 'public_url', 'public_url_set', 'data_dir', 'config_dir', 'proxy_require_login', 'trust_proxy_headers', 'version', 'commit'];
      const table = document.createElement('table');
      const tbody = document.createElement('tbody');
      for (const column of columns) {
        const row = document.createElement('tr');
        const th = document.createElement('th');
        th.textContent = column;
        const td = document.createElement('td');
        td.textContent = String(data[column] ?? '');
        row.appendChild(th);
        row.appendChild(td);
        tbody.appendChild(row);
      }
      table.appendChild(tbody);
      systemInfo.textContent = '';
      systemInfo.appendChild(table);
    }

    function showAPIKeyResponse(result) {
      const value = unwrap(result);
      if (value && value.token) {
        show({ warning: 'Copy this token now. It will not be shown again.', api_key: value });
        return;
      }
      show(result);
    }

    async function loadResources() {
      const result = await api('/api/v1/resources');
      const data = unwrap(result);
      resources = data.resources || [];
      renderResources();
      show(result);
    }

    async function validateResource(resource) {
      try { show(await api('/api/v1/resources/validate', { method: 'POST', body: JSON.stringify(resource) })); } catch (err) { show(err); }
    }

    function downloadJSON(filename, value) {
      const json = JSON.stringify(value, null, 2);
      const blob = new Blob([json + '\n'], { type: 'application/json' });
      const link = document.createElement('a');
      link.href = URL.createObjectURL(blob);
      link.download = filename;
      link.click();
      URL.revokeObjectURL(link.href);
      show(json);
    }

    async function testRule() {
      const target = document.querySelector('#url').value.trim();
      const result = await api('/api/v1/rules/test-url', {
        method: 'POST',
        body: JSON.stringify({ url: target })
      });
      const body = unwrap(result) || {};
      const enriched = { ...body, proxy_url: target ? proxyURL(target) : '', selected_resource_id: selectedResourceId || '' };
      resourceTestOutput.textContent = JSON.stringify(enriched, null, 2);
      show({ ...result, body: enriched });
    }

    async function fetchThroughProxy() {
      const target = document.querySelector('#url').value.trim();
      const result = await api('/api/v1/proxy/test-fetch', {
        method: 'POST',
        body: JSON.stringify({ url: target })
      });
      const body = unwrap(result) || {};
      const enriched = { ...body, proxy_url: target ? proxyURL(target) : '', selected_resource_id: selectedResourceId || '' };
      resourceTestOutput.textContent = JSON.stringify(enriched, null, 2);
      show({ ...result, body: enriched });
    }

    async function loadConfigRevisions() {
      show(await api('/api/v1/config/revisions'));
    }

    async function loadAccessLogs() {
      show(await api('/api/v1/logs/access/recent'));
    }

    async function loadProxyDiagnostics() {
      show(await api('/api/v1/diagnostics/proxy/recent'));
    }

    async function loadMissedRewrites() {
      const result = await api('/api/v1/diagnostics/missed-rewrites/recent');
      show({ ...result, body: summarizeMissedRewrites(unwrap(result)) });
    }

    async function loadAPIKeys(showResult = true) {
      const result = await api('/api/v1/api-keys');
      const data = unwrap(result);
      apiKeys = data.api_keys || [];
      renderAPIKeys();
      if (showResult) show(result);
    }

    async function loadUsers(showResult = true) {
      const result = await api('/api/v1/users');
      const data = unwrap(result);
      users = data.users || [];
      renderUsers();
      if (showResult) show(result);
    }

    async function loadSAMLProviders(showResult = true) {
      const result = await api('/api/v1/auth/saml/providers');
      const data = unwrap(result);
      samlProviders = data.providers || [];
      renderSAMLProviders();
      if (showResult) show(result);
    }

    document.querySelector('#dash-health').addEventListener('click', async () => { try { show(await api('/api/v1/health', { auth: false })); } catch (err) { show(err); } });
    document.querySelector('#dash-openapi').addEventListener('click', () => window.open('/openapi.yaml', '_blank', 'noopener'));
    document.querySelector('#dash-resources').addEventListener('click', async () => { switchSection('resources'); try { await loadResources(); } catch (err) { show(err); } });
    document.querySelector('#dash-revisions').addEventListener('click', async () => { switchSection('config'); try { await loadConfigRevisions(); } catch (err) { show(err); } });
    document.querySelector('#dash-access-logs').addEventListener('click', async () => { switchSection('diagnostics'); try { await loadAccessLogs(); } catch (err) { show(err); } });
    document.querySelector('#dash-proxy-diagnostics').addEventListener('click', async () => { switchSection('diagnostics'); try { await loadProxyDiagnostics(); } catch (err) { show(err); } });
    document.querySelector('#dash-missed-rewrites').addEventListener('click', async () => { switchSection('diagnostics'); try { await loadMissedRewrites(); } catch (err) { show(err); } });
    document.querySelector('#dash-api-keys').addEventListener('click', async () => { switchSection('api-keys'); try { await loadAPIKeys(); } catch (err) { show(err); } });
    document.querySelector('#dash-users').addEventListener('click', async () => { switchSection('users'); try { await loadUsers(); } catch (err) { show(err); } });

    document.querySelector('#load').addEventListener('click', async () => { try { await loadResources(); } catch (err) { show(err); } });
    document.querySelector('#new-resource').addEventListener('click', () => { setEditor(template); show('New resource template loaded.'); });
    document.querySelector('#save-resource').addEventListener('click', async () => {
      const resource = parseJSONEditor(editor, 'resource');
      if (!resource) return;
      try {
        const result = await api('/api/v1/resources', { method: 'POST', body: JSON.stringify(resource) });
        show(result);
        await loadResources();
        setEditor(unwrap(result));
      } catch (err) { show(err); }
    });
    document.querySelector('#delete-resource').addEventListener('click', async () => {
      const resource = parseJSONEditor(editor, 'resource');
      if (!resource) return;
      if (!resource.id) { show({ error: 'resource id is required before delete' }); return; }
      if (!confirm('Delete resource "' + resource.id + '"?')) return;
      try {
        show(await api('/api/v1/resources/' + encodeURIComponent(resource.id), { method: 'DELETE' }));
        editor.value = '';
        selectedResourceId = '';
        await loadResources();
      } catch (err) { show(err); }
    });
    document.querySelector('#add-domain').addEventListener('click', () => addDomainRow());
    document.querySelector('#add-anonymous-rule').addEventListener('click', () => addAnonymousRuleRow());
    document.querySelector('#add-header-rule').addEventListener('click', () => addHeaderRuleRow());
    document.querySelector('#add-rewrite-rule').addEventListener('click', () => addRewriteRuleRow());
    document.querySelector('#generate-json').addEventListener('click', () => {
      const resource = buildResourceConfig();
      setEditor(resource);
      show(resource);
    });
    document.querySelector('#validate-json').addEventListener('click', async () => {
      const resource = parseJSONEditor(editor, 'resource') || buildResourceConfig();
      await validateResource(resource);
    });
    document.querySelector('#save-builder-resource').addEventListener('click', async () => {
      const resource = buildResourceConfig();
      setEditor(resource);
      try {
        const result = await api('/api/v1/resources', { method: 'POST', body: JSON.stringify(resource) });
        show(result);
        await loadResources();
      } catch (err) { show(err); }
    });
    document.querySelector('#export-json').addEventListener('click', () => {
      const resource = parseJSONEditor(editor, 'resource') || buildResourceConfig();
      downloadJSON('resource-' + (resource.id || 'new-resource') + '.json', resource);
    });
    document.querySelector('#load-existing-builder').addEventListener('click', () => {
      const resource = parseJSONEditor(editor, 'resource');
      if (!resource) return;
      loadBuilder(resource);
      show('Resource loaded into builder.');
    });

    document.querySelector('#validate').addEventListener('click', async () => { try { show(await api('/api/v1/config/validate', { method: 'POST' })); } catch (err) { show(err); } });
    document.querySelector('#import').addEventListener('click', async () => { try { show(await api('/api/v1/config/import', { method: 'POST' })); } catch (err) { show(err); } });
    document.querySelector('#revisions').addEventListener('click', async () => { try { await loadConfigRevisions(); } catch (err) { show(err); } });

    document.querySelector('#test').addEventListener('click', async () => {
      try { await testRule(); } catch (err) { show(err); }
    });
    document.querySelector('#open-proxy').addEventListener('click', () => {
      const target = document.querySelector('#url').value.trim();
      if (!target) { show({ error: 'target URL is required' }); return; }
      try { window.open(proxyURL(target), '_blank', 'noopener'); } catch (err) { show({ error: 'target URL is invalid', detail: err.message }); }
    });
    document.querySelector('#fetch-proxy').addEventListener('click', async () => {
      try { await fetchThroughProxy(); } catch (err) { show(err); }
    });
    document.querySelector('#resource-missed-rewrites').addEventListener('click', async () => { try { await loadMissedRewrites(); } catch (err) { show(err); } });
    document.querySelector('#export-filtered-json').addEventListener('click', () => downloadJSON('resources-export.json', filteredResources()));
    for (const control of [resourceSearch, resourceStatusFilter, resourceBehaviorFilter, resourceComplexityFilter, resourceTagFilter, resourceSort, resourceOrder]) {
      control.addEventListener('input', renderResources);
      control.addEventListener('change', renderResources);
    }

    document.querySelector('#access-logs').addEventListener('click', async () => { try { await loadAccessLogs(); } catch (err) { show(err); } });
    document.querySelector('#proxy-diagnostics').addEventListener('click', async () => { try { await loadProxyDiagnostics(); } catch (err) { show(err); } });
    document.querySelector('#missed-rewrites').addEventListener('click', async () => { try { await loadMissedRewrites(); } catch (err) { show(err); } });

    document.querySelector('#load-api-keys').addEventListener('click', async () => { try { await loadAPIKeys(); } catch (err) { show(err); } });
    document.querySelector('#new-api-key').addEventListener('click', () => {
      selectedAPIKeyId = '';
      apiKeyEditor.value = JSON.stringify(apiKeyTemplate, null, 2);
      renderAPIKeys();
      show('New API key template loaded.');
    });
    document.querySelector('#create-api-key').addEventListener('click', async () => {
      const body = parseJSONEditor(apiKeyEditor, 'api key');
      if (!body) return;
      try {
        const result = await api('/api/v1/api-keys', { method: 'POST', body: JSON.stringify(body) });
        const created = unwrap(result);
        selectedAPIKeyId = created.id || '';
        showAPIKeyResponse(result);
        await loadAPIKeys(false);
      } catch (err) { show(err); }
    });
    document.querySelector('#rotate-api-key').addEventListener('click', async () => {
      const id = selectedAPIKeyId || (parseJSONEditor(apiKeyEditor, 'api key') || {}).id;
      if (!id) { show({ error: 'api key id is required' }); return; }
      try { showAPIKeyResponse(await api('/api/v1/api-keys/' + encodeURIComponent(id) + '/rotate', { method: 'POST' })); } catch (err) { show(err); }
    });
    document.querySelector('#revoke-api-key').addEventListener('click', async () => {
      const id = selectedAPIKeyId || (parseJSONEditor(apiKeyEditor, 'api key') || {}).id;
      if (!id) { show({ error: 'api key id is required' }); return; }
      if (!confirm('Revoke API key "' + id + '"?')) return;
      try { show(await api('/api/v1/api-keys/' + encodeURIComponent(id) + '/revoke', { method: 'POST' })); await loadAPIKeys(); } catch (err) { show(err); }
    });
    document.querySelector('#delete-api-key').addEventListener('click', async () => {
      const id = selectedAPIKeyId || (parseJSONEditor(apiKeyEditor, 'api key') || {}).id;
      if (!id) { show({ error: 'api key id is required' }); return; }
      if (!confirm('Delete API key "' + id + '"?')) return;
      try { show(await api('/api/v1/api-keys/' + encodeURIComponent(id), { method: 'DELETE' })); await loadAPIKeys(); } catch (err) { show(err); }
    });

    document.querySelector('#load-users').addEventListener('click', async () => { try { await loadUsers(); } catch (err) { show(err); } });
    document.querySelector('#new-user').addEventListener('click', () => {
      selectedUserId = '';
      userEditor.value = JSON.stringify(userTemplate, null, 2);
      document.querySelector('#user-password').value = '';
      renderUsers();
      show('New user template loaded.');
    });
    document.querySelector('#create-user').addEventListener('click', async () => {
      const user = parseJSONEditor(userEditor, 'user');
      if (!user) return;
      const password = document.querySelector('#user-password').value;
      if (password) user.password = password;
      try {
        const result = await api('/api/v1/users', { method: 'POST', body: JSON.stringify(user) });
        const created = unwrap(result);
        selectedUserId = created.id || '';
        document.querySelector('#user-password').value = '';
        show(result);
        await loadUsers(false);
      } catch (err) { show(err); }
    });
    document.querySelector('#update-user').addEventListener('click', async () => {
      const user = parseJSONEditor(userEditor, 'user');
      const id = selectedUserId || (user || {}).id;
      if (!user || !id) { show({ error: 'user id is required' }); return; }
      try {
        const result = await api('/api/v1/users/' + encodeURIComponent(id), {
          method: 'PATCH',
          body: JSON.stringify({
            email: user.email || '',
            display_name: user.display_name || '',
            roles: user.roles || [],
            status: user.status || 'active'
          })
        });
        show(result);
        await loadUsers(false);
      } catch (err) { show(err); }
    });
    document.querySelector('#set-user-password').addEventListener('click', async () => {
      const user = parseJSONEditor(userEditor, 'user');
      const id = selectedUserId || (user || {}).id;
      const password = document.querySelector('#user-password').value;
      if (!id) { show({ error: 'user id is required' }); return; }
      if (!password) { show({ error: 'new password is required' }); return; }
      try { show(await api('/api/v1/users/' + encodeURIComponent(id) + '/set-password', { method: 'POST', body: JSON.stringify({ password }) })); document.querySelector('#user-password').value = ''; } catch (err) { show(err); }
    });
    async function userAction(action, confirmText) {
      const user = parseJSONEditor(userEditor, 'user');
      const id = selectedUserId || (user || {}).id;
      if (!id) { show({ error: 'user id is required' }); return; }
      if (confirmText && !confirm(confirmText.replace('{id}', id))) return;
      try { show(await api('/api/v1/users/' + encodeURIComponent(id) + '/' + action, { method: 'POST' })); await loadUsers(false); } catch (err) { show(err); }
    }
    document.querySelector('#disable-user').addEventListener('click', () => userAction('disable', 'Disable user "{id}"?'));
    document.querySelector('#enable-user').addEventListener('click', () => userAction('enable'));
    document.querySelector('#lock-user').addEventListener('click', () => userAction('lock', 'Lock user "{id}"?'));
    document.querySelector('#unlock-user').addEventListener('click', () => userAction('unlock'));
    document.querySelector('#revoke-user-sessions').addEventListener('click', () => userAction('revoke-sessions', 'Revoke all sessions for user "{id}"?'));

    document.querySelector('#settings-health').addEventListener('click', async () => { try { show(await api('/api/v1/health', { auth: false })); } catch (err) { show(err); } });
    document.querySelector('#settings-system').addEventListener('click', async () => {
      try {
        const result = await api('/api/v1/system');
        renderSystemInfo(unwrap(result));
        show(result);
      } catch (err) { show(err); }
    });
    document.querySelector('#settings-openapi').addEventListener('click', () => window.open('/openapi.yaml', '_blank', 'noopener'));

    document.querySelector('#load-saml-providers').addEventListener('click', async () => { try { await loadSAMLProviders(); } catch (err) { show(err); } });
    document.querySelector('#new-saml-provider').addEventListener('click', () => {
      selectedSAMLProviderId = '';
      samlEditor.value = JSON.stringify(samlProviderTemplate, null, 2);
      renderSAMLProviders();
      show('New SAML provider template loaded.');
    });
    document.querySelector('#save-saml-provider').addEventListener('click', async () => {
      const provider = parseJSONEditor(samlEditor, 'saml provider');
      if (!provider) return;
      try {
        const result = await api('/api/v1/auth/saml/providers', { method: 'POST', body: JSON.stringify(provider) });
        const saved = unwrap(result);
        selectedSAMLProviderId = saved.id || '';
        show(result);
        await loadSAMLProviders(false);
      } catch (err) { show(err); }
    });
    document.querySelector('#delete-saml-provider').addEventListener('click', async () => {
      const provider = parseJSONEditor(samlEditor, 'saml provider');
      const id = selectedSAMLProviderId || (provider || {}).id;
      if (!id) { show({ error: 'saml provider id is required' }); return; }
      if (!confirm('Delete SAML provider "' + id + '"?')) return;
      try { show(await api('/api/v1/auth/saml/providers/' + encodeURIComponent(id), { method: 'DELETE' })); await loadSAMLProviders(false); } catch (err) { show(err); }
    });
    document.querySelector('#open-saml-metadata').addEventListener('click', () => window.open('/auth/saml/metadata', '_blank', 'noopener'));

    addDomainRow();
    addHeaderRuleRow({ name: 'X-Requested-With', action: 'remove', phase: 'request' });
    addAnonymousRuleRow();
    addRewriteRuleRow();
    loadSession();
  </script>
</body>
</html>`
}
