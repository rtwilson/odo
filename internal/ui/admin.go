package ui

func AdminHTML() string {
	return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>odo admin</title>
  <style>
    :root { color-scheme: dark; font-family: Inter, ui-sans-serif, system-ui, sans-serif; background: #111315; color: #f2f4f7; }
    body { margin: 0; }
    main { max-width: 1180px; margin: 0 auto; padding: 32px 20px; }
    header { display: flex; align-items: baseline; justify-content: space-between; gap: 16px; border-bottom: 1px solid #2a2f36; padding-bottom: 18px; }
    a { color: #8cc7ff; text-decoration: none; }
    a:hover { text-decoration: underline; }
    h1 { margin: 0; font-size: 28px; letter-spacing: 0; }
    section { margin-top: 24px; }
    .toolbar { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; }
    .workspace { display: grid; grid-template-columns: 280px minmax(0, 1fr); gap: 18px; align-items: start; }
    button, input, textarea { border: 1px solid #3a414b; background: #181c20; color: #f2f4f7; border-radius: 6px; padding: 10px 12px; font: inherit; }
    button { cursor: pointer; background: #245c45; border-color: #327957; }
    button:hover { background: #2c704f; }
    button.danger { background: #6b2f35; border-color: #9b3f49; }
    button.danger:hover { background: #7d3840; }
    input { min-width: min(520px, 100%); }
    textarea { width: 100%; min-height: 480px; box-sizing: border-box; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; line-height: 1.45; resize: vertical; }
    pre, .list { overflow: auto; background: #181c20; border: 1px solid #2a2f36; border-radius: 8px; padding: 12px; line-height: 1.45; }
    .list { min-height: 480px; }
    .resource-item { display: block; width: 100%; text-align: left; margin-bottom: 8px; background: #1f252b; border-color: #303841; }
    .resource-item.active { background: #2c704f; border-color: #3f946a; }
    .sample { display: block; width: 100%; text-align: left; margin: 6px 0 10px; background: #222831; border-color: #39424d; color: #cfe4ff; }
    .panel-title { width: 100%; margin: 0 0 4px; font-size: 18px; }
    .muted { color: #a8b0ba; }
    @media (max-width: 820px) { .workspace { grid-template-columns: 1fr; } }
  </style>
</head>
<body>
  <main>
    <header>
      <h1>odo admin</h1>
      <span class="muted"><a href="/openapi.yaml">OpenAPI spec</a></span>
    </header>

    <section class="toolbar">
      <input id="api-key" type="password" placeholder="Admin API Key" aria-label="Admin API Key">
      <button id="load">Load Resources</button>
      <button id="new-resource">New Resource</button>
      <button id="save-resource">Save Resource</button>
      <button id="delete-resource" class="danger">Delete Resource</button>
    </section>

    <section class="workspace">
      <aside>
        <div id="resource-list" class="list">No resources loaded.</div>
      </aside>
      <div>
        <textarea id="editor" spellcheck="false" aria-label="Resource JSON editor"></textarea>
      </div>
    </section>

    <section class="toolbar">
      <button id="validate">Validate Config</button>
      <button id="import">Import config files</button>
      <button id="revisions">Load Config Revisions</button>
    </section>

    <section class="toolbar">
      <h2 class="panel-title">Proxy Test</h2>
      <input id="url" value="https://www.jstor.org/stable/example" aria-label="Target URL">
      <button id="test">Test Rule</button>
      <button id="open-proxy">Open Through Proxy</button>
      <button id="fetch-proxy">Fetch Through Proxy</button>
    </section>

    <section class="toolbar">
      <h2 class="panel-title">Logs and Diagnostics</h2>
      <button id="access-logs">Load Access Logs</button>
      <button id="proxy-diagnostics">Load Proxy Diagnostics</button>
    </section>

    <section>
      <pre id="output">Ready.</pre>
    </section>
  </main>

  <script>
    const output = document.querySelector('#output');
    const editor = document.querySelector('#editor');
    const list = document.querySelector('#resource-list');
    let resources = [];
    let selectedId = '';

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

    const show = value => output.textContent = typeof value === 'string' ? value : JSON.stringify(value, null, 2);

    async function api(path, options = {}) {
      const response = await fetch(path, {
        ...options,
        headers: headers(options.headers)
      });
      const json = await response.json();
      if (!response.ok) throw json;
      return json;
    }

    function headers(extra = {}) {
      const apiKey = document.querySelector('#api-key').value.trim();
      return {
        'Content-Type': 'application/json',
        ...(apiKey ? { 'Authorization': 'Bearer ' + apiKey } : {}),
        ...extra
      };
    }

    function setEditor(value) {
      editor.value = JSON.stringify(value, null, 2);
      selectedId = value.id || '';
      renderList();
    }

    function parseEditor() {
      try {
        return JSON.parse(editor.value);
      } catch (err) {
        show({ error: 'editor JSON is invalid', detail: err.message });
        return null;
      }
    }

    function renderList() {
      if (!resources.length) {
        list.textContent = 'No resources loaded.';
        return;
      }
      list.textContent = '';
      for (const resource of resources) {
        const button = document.createElement('button');
        button.className = 'resource-item' + (resource.id === selectedId ? ' active' : '');
        button.textContent = resource.id + ' - ' + resource.name;
        button.addEventListener('click', () => setEditor(resource));
        list.appendChild(button);
        for (const sampleURL of resource.sample_urls || []) {
          const sample = document.createElement('button');
          sample.className = 'sample';
          sample.textContent = sampleURL;
          sample.addEventListener('click', () => {
            document.querySelector('#url').value = sampleURL;
            setEditor(resource);
            show({ selected_sample_url: sampleURL });
          });
          list.appendChild(sample);
        }
      }
    }

    async function loadResources() {
      const data = await api('/api/v1/resources');
      resources = data.resources || [];
      renderList();
      show(data);
    }

    document.querySelector('#load').addEventListener('click', async () => {
      try { await loadResources(); } catch (err) { show(err); }
    });

    document.querySelector('#new-resource').addEventListener('click', () => {
      setEditor(template);
      show('New resource template loaded.');
    });

    document.querySelector('#save-resource').addEventListener('click', async () => {
      const resource = parseEditor();
      if (!resource) return;
      try {
        const saved = await api('/api/v1/resources', {
          method: 'POST',
          body: JSON.stringify(resource)
        });
        show(saved);
        await loadResources();
        setEditor(saved);
      } catch (err) { show(err); }
    });

    document.querySelector('#delete-resource').addEventListener('click', async () => {
      const resource = parseEditor();
      if (!resource) return;
      if (!resource.id) {
        show({ error: 'resource id is required before delete' });
        return;
      }
      if (!confirm('Delete resource "' + resource.id + '"?')) return;
      try {
        const deleted = await api('/api/v1/resources/' + encodeURIComponent(resource.id), { method: 'DELETE' });
        show(deleted);
        editor.value = '';
        selectedId = '';
        await loadResources();
      } catch (err) { show(err); }
    });

    document.querySelector('#validate').addEventListener('click', async () => {
      try { show(await api('/api/v1/config/validate', { method: 'POST' })); } catch (err) { show(err); }
    });

    document.querySelector('#import').addEventListener('click', async () => {
      try { show(await api('/api/v1/config/import', { method: 'POST' })); } catch (err) { show(err); }
    });

    document.querySelector('#revisions').addEventListener('click', async () => {
      try { show(await api('/api/v1/config/revisions')); } catch (err) { show(err); }
    });

    document.querySelector('#test').addEventListener('click', async () => {
      try {
        show(await api('/api/v1/rules/test-url', {
          method: 'POST',
          body: JSON.stringify({ url: document.querySelector('#url').value })
        }));
      } catch (err) { show(err); }
    });

    document.querySelector('#open-proxy').addEventListener('click', () => {
      const target = document.querySelector('#url').value.trim();
      if (!target) {
        show({ error: 'target URL is required' });
        return;
      }
      window.open('/p?url=' + encodeURIComponent(target), '_blank', 'noopener');
    });

    document.querySelector('#fetch-proxy').addEventListener('click', async () => {
      try {
        show(await api('/api/v1/proxy/test-fetch', {
          method: 'POST',
          body: JSON.stringify({ url: document.querySelector('#url').value })
        }));
      } catch (err) { show(err); }
    });

    document.querySelector('#access-logs').addEventListener('click', async () => {
      try { show(await api('/api/v1/logs/access/recent')); } catch (err) { show(err); }
    });

    document.querySelector('#proxy-diagnostics').addEventListener('click', async () => {
      try { show(await api('/api/v1/diagnostics/proxy/recent')); } catch (err) { show(err); }
    });
  </script>
</body>
</html>`
}
