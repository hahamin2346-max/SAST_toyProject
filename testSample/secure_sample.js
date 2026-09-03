// Secure JavaScript sample - the baseline detectors should report nothing here.
const { execFile } = require('node:child_process');
const path = require('node:path');

function search(req, res) {
  const sql = 'SELECT * FROM users WHERE name = ?';
  db.query(sql, [req.query.name], (err, rows) => res.json(rows));

  document.getElementById('out').textContent = req.query.name;

  const safeName = path.basename(req.query.file);
  fs.readFile(path.join('/data', safeName), 'utf8', (e, d) => res.send(escapeHtml(d)));

  execFile('ping', [sanitizeHost(req.query.host)]);
}

const apiKey = process.env.API_KEY;
