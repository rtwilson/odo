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
    textarea { width: 100%; min-height: 340px; box-sizing: border-box; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; line-height: 1.45; resize: vertical; }
    pre, .list, .table-wrap { overflow: auto; background: #181d22; border: 1px solid #2b3138; border-radius: 8px; padding: 12px; line-height: 1.45; }
    .section { display: none; }
    .section.active { display: block; }
    .toolbar { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; margin: 10px 0 16px; }
    .workspace { display: grid; grid-template-columns: 290px minmax(0, 1fr); gap: 18px; align-items: start; }
    .list { min-height: 340px; }
    .resource-item, .api-key-row { display: block; width: 100%; text-align: left; margin-bottom: 8px; background: #1f262d; border-color: #303943; }
    .resource-item.active, .api-key-row.active { background: #2c704f; border-color: #3f946a; }
    .sample { display: block; width: 100%; text-align: left; margin: 6px 0 10px; background: #222a32; border-color: #39424d; color: #cfe4ff; }
    table { width: 100%; border-collapse: collapse; min-width: 860px; }
    th, td { border-bottom: 1px solid #2b3138; padding: 8px; text-align: left; vertical-align: top; }
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
      <span class="muted">Used only in this page runtime for protected API calls.</span>
    </section>

    <div class="layout">
      <nav aria-label="Admin sections">
        <button class="nav-button active" data-section="dashboard">Dashboard</button>
        <button class="nav-button" data-section="resources">Resources</button>
        <button class="nav-button" data-section="config">Config</button>
        <button class="nav-button" data-section="proxy">Proxy Test</button>
        <button class="nav-button" data-section="diagnostics">Diagnostics / Logs</button>
        <button class="nav-button" data-section="api-keys">API Keys</button>
        <button class="nav-button" data-section="auth">Auth / SAML</button>
        <button class="nav-button" data-section="settings">Settings / System</button>
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
          </div>
        </section>

        <section id="section-resources" class="section">
          <h2>Resources</h2>
          <div class="toolbar">
            <button id="load">Load Resources</button>
            <button id="new-resource">New Resource</button>
            <button id="save-resource">Save Resource</button>
            <button id="delete-resource" class="danger">Delete Resource</button>
          </div>
          <div class="workspace">
            <aside><div id="resource-list" class="list">No resources loaded.</div></aside>
            <div><textarea id="editor" spellcheck="false" aria-label="Resource JSON editor"></textarea></div>
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

        <section id="section-proxy" class="section">
          <h2>Proxy Test</h2>
          <div class="toolbar">
            <input id="url" value="https://www.jstor.org/stable/example" aria-label="Target URL">
            <button id="test">Test Rule</button>
            <button id="open-proxy">Open Through Proxy</button>
            <button id="fetch-proxy">Fetch Through Proxy</button>
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
            <button id="settings-openapi">OpenAPI spec</button>
          </div>
          <p class="muted">Runtime configuration is controlled by environment variables. Secrets are not displayed here.</p>
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
    const samlEditor = document.querySelector('#saml-editor');
    const resourceList = document.querySelector('#resource-list');
    const apiKeyTable = document.querySelector('#api-key-table');
    const samlProviderList = document.querySelector('#saml-provider-list');
    let resources = [];
    let apiKeys = [];
    let samlProviders = [];
    let selectedResourceId = '';
    let selectedAPIKeyId = '';
    let selectedSAMLProviderId = '';

    const template = {
      id: 'new-resource',
      name: 'New Resource',
      status: 'active',
      description: '',
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
      return {
        'Content-Type': 'application/json',
        ...(needsAuth && apiKey ? { 'Authorization': 'Bearer ' + apiKey } : {}),
        ...extra
      };
    }

    async function api(path, options = {}) {
      const method = options.method || 'GET';
      const needsAuth = options.auth !== false;
      const headers = adminHeaders(options.headers, needsAuth);
      if (needsAuth && !headers.Authorization) {
        show({ message: 'Authorization is missing. Enter an Admin API Key for protected requests.', method, url: path });
      }
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

    function proxyURL(raw) {
      const target = new URL(raw);
      return '/odo/https/' + target.host + target.pathname + target.search;
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
      renderResources();
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
      if (!resources.length) {
        resourceList.textContent = 'No resources loaded.';
        return;
      }
      resourceList.textContent = '';
      for (const resource of resources) {
        const button = document.createElement('button');
        button.className = 'resource-item' + (resource.id === selectedResourceId ? ' active' : '');
        button.textContent = resource.id + ' - ' + resource.name;
        button.addEventListener('click', () => setEditor(resource));
        resourceList.appendChild(button);
        for (const sampleURL of resource.sample_urls || []) {
          const sample = document.createElement('button');
          sample.className = 'sample';
          sample.textContent = sampleURL;
          sample.addEventListener('click', () => {
            document.querySelector('#url').value = sampleURL;
            setEditor(resource);
            show({ selected_sample_url: sampleURL });
          });
          resourceList.appendChild(sample);
        }
      }
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

    function showAPIKeyResponse(result) {
      const value = unwrap(result);
      if (value && value.token) {
        show({ warning: 'Copy this token now. It will not be shown again.', api_key: value });
        return;
      }
      show(result);
    }

    async function loadResources() {
      const result = await api('/api/v1/resources', { auth: false });
      const data = unwrap(result);
      resources = data.resources || [];
      renderResources();
      show(result);
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

    document.querySelector('#validate').addEventListener('click', async () => { try { show(await api('/api/v1/config/validate', { method: 'POST' })); } catch (err) { show(err); } });
    document.querySelector('#import').addEventListener('click', async () => { try { show(await api('/api/v1/config/import', { method: 'POST' })); } catch (err) { show(err); } });
    document.querySelector('#revisions').addEventListener('click', async () => { try { await loadConfigRevisions(); } catch (err) { show(err); } });

    document.querySelector('#test').addEventListener('click', async () => {
      try {
        show(await api('/api/v1/rules/test-url', {
          method: 'POST',
          auth: false,
          body: JSON.stringify({ url: document.querySelector('#url').value })
        }));
      } catch (err) { show(err); }
    });
    document.querySelector('#open-proxy').addEventListener('click', () => {
      const target = document.querySelector('#url').value.trim();
      if (!target) { show({ error: 'target URL is required' }); return; }
      try { window.open(proxyURL(target), '_blank', 'noopener'); } catch (err) { show({ error: 'target URL is invalid', detail: err.message }); }
    });
    document.querySelector('#fetch-proxy').addEventListener('click', async () => {
      try {
        show(await api('/api/v1/proxy/test-fetch', {
          method: 'POST',
          body: JSON.stringify({ url: document.querySelector('#url').value })
        }));
      } catch (err) { show(err); }
    });

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

    document.querySelector('#settings-health').addEventListener('click', async () => { try { show(await api('/api/v1/health', { auth: false })); } catch (err) { show(err); } });
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
  </script>
</body>
</html>`
}
