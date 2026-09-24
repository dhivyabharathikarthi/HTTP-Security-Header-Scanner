import express from 'express';
import { createServer as createViteServer } from 'vite';
import { execFile } from 'child_process';
import path from 'path';
import fs from 'fs';
import { promisify } from 'util';

const execFileAsync = promisify(execFile);
const app = express();
const PORT = 3000;

app.use(express.json());

// API Routes
app.post('/api/scan', async (req, res) => {
  const { url } = req.body;
  if (!url || typeof url !== 'string') {
    return res.status(400).json({ detail: 'Target URL is required.' });
  }

  try {
    // Run the defensive Python scanner CLI
    const pythonExe = 'python3';
    const { stdout, stderr } = await execFileAsync(pythonExe, ['-m', 'app.cli', url], {
      timeout: 15000,
      maxBuffer: 10 * 1024 * 1024,
      env: { ...process.env, PYTHONPATH: '.' }
    });

    const parsed = JSON.parse(stdout.trim());
    if (parsed.error) {
      return res.status(400).json({ detail: parsed.error });
    }
    return res.json(parsed);
  } catch (err: any) {
    console.error('Scan execution error:', err);
    let errMsg = err.message || 'Scan failed.';
    try {
      if (err.stdout) {
        const p = JSON.parse(err.stdout);
        if (p.error) errMsg = p.error;
      }
    } catch (_) {}
    return res.status(502).json({ detail: errMsg });
  }
});

app.get('/api/scans', async (req, res) => {
  try {
    // Query SQLite scans via python script
    const pyScript = `
import json, sqlite3
conn = sqlite3.connect('scans.db')
conn.row_factory = sqlite3.Row
c = conn.cursor()
c.execute("CREATE TABLE IF NOT EXISTS scans (id TEXT PRIMARY KEY, original_url TEXT, final_url TEXT, timestamp TEXT, status_code INTEGER, score INTEGER, max_score INTEGER, result_json TEXT)")
c.execute("SELECT id, original_url, final_url, timestamp, status_code, score, max_score FROM scans ORDER BY timestamp DESC LIMIT 50")
rows = [dict(r) for r in c.fetchall()]
for r in rows:
    r['is_https'] = r['final_url'].lower().startswith('https://')
print(json.dumps(rows))
`;
    const { stdout } = await execFileAsync('python3', ['-c', pyScript]);
    const list = JSON.parse(stdout.trim() || '[]');
    return res.json(list);
  } catch (err: any) {
    console.error('History fetch error:', err);
    return res.json([]);
  }
});

app.get('/api/scans/:id', async (req, res) => {
  const scanId = req.params.id;
  try {
    const pyScript = `
import json, sqlite3, sys
conn = sqlite3.connect('scans.db')
conn.row_factory = sqlite3.Row
c = conn.cursor()
c.execute("SELECT result_json FROM scans WHERE id = ?", (sys.argv[1],))
row = c.fetchone()
if row:
    print(row['result_json'])
else:
    print(json.dumps({"error": "Scan not found"}))
`;
    const { stdout } = await execFileAsync('python3', ['-c', pyScript, scanId]);
    const data = JSON.parse(stdout.trim());
    if (data.error) {
      return res.status(404).json({ detail: data.error });
    }
    return res.json(data);
  } catch (err: any) {
    return res.status(500).json({ detail: err.message });
  }
});

app.get('/api/scans/:id/json', async (req, res) => {
  const scanId = req.params.id;
  try {
    const pyScript = `
import json, sqlite3, sys
conn = sqlite3.connect('scans.db')
conn.row_factory = sqlite3.Row
c = conn.cursor()
c.execute("SELECT result_json FROM scans WHERE id = ?", (sys.argv[1],))
row = c.fetchone()
if row:
    print(row['result_json'])
else:
    print(json.dumps({"error": "Scan not found"}))
`;
    const { stdout } = await execFileAsync('python3', ['-c', pyScript, scanId]);
    const data = JSON.parse(stdout.trim());
    if (data.error) {
      return res.status(404).json({ detail: data.error });
    }
    res.setHeader('Content-Disposition', `attachment; filename=security_scan_${scanId.slice(0, 8)}.json`);
    res.setHeader('Content-Type', 'application/json');
    return res.send(stdout.trim());
  } catch (err: any) {
    return res.status(500).json({ detail: err.message });
  }
});

async function startServer() {
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static('dist'));
    app.get('*', (req, res) => {
      res.sendFile(path.resolve(__dirname, 'dist/index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server listening on http://0.0.0.0:${PORT}`);
  });
}

startServer();
