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
    main { max-width: 980px; margin: 0 auto; padding: 32px 20px; }
    header { display: flex; align-items: baseline; justify-content: space-between; gap: 16px; border-bottom: 1px solid #2a2f36; padding-bottom: 18px; }
    a { color: #8cc7ff; text-decoration: none; }
    a:hover { text-decoration: underline; }
    h1 { margin: 0; font-size: 28px; letter-spacing: 0; }
    section { margin-top: 24px; }
    .toolbar { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; }
    button, input { border: 1px solid #3a414b; background: #181c20; color: #f2f4f7; border-radius: 6px; padding: 10px 12px; font: inherit; }
    button { cursor: pointer; background: #245c45; border-color: #327957; }
    button:hover { background: #2c704f; }
    input { min-width: min(520px, 100%); }
    pre { overflow: auto; background: #181c20; border: 1px solid #2a2f36; border-radius: 8px; padding: 16px; line-height: 1.45; }
    .muted { color: #a8b0ba; }
  </style>
</head>
<body>
  <main>
    <header>
      <h1>odo admin</h1>
      <span class="muted"><a href="/openapi.yaml">OpenAPI spec</a></span>
    </header>

    <section class="toolbar">
      <input id="api-key" type="password" placeholder="Admin API key" aria-label="Admin API key">
      <button id="load">Load resources</button>
      <button id="validate">Validate Config</button>
      <button id="import">Import config files</button>
      <button id="revisions">Load Config Revisions</button>
      <input id="url" value="https://www.jstor.org/stable/example" aria-label="URL to test">
      <button id="test">Test URL</button>
    </section>

    <section>
      <pre id="output">Ready.</pre>
    </section>
  </main>

  <script>
    const output = document.querySelector('#output');
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

    document.querySelector('#load').addEventListener('click', async () => {
      try { show(await api('/api/v1/resources')); } catch (err) { show(err); }
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
  </script>
</body>
</html>`
}
