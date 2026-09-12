const express = require('express');
const path = require('path');
const fs = require('fs');
const os = require('os');
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');
const ffmpegPath = require('ffmpeg-static');
const ffmpeg = require('fluent-ffmpeg');
const cors = require('cors');
const crypto = require('crypto');
const dns = require('dns');
const net = require('net');

ffmpeg.setFfmpegPath(ffmpegPath);

const app = express();
const PORT = process.env.PORT || 3000;

// Security headers required for WASM shared array buffer processing
app.use((req, res, next) => {
  res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  res.setHeader("Cross-Origin-Embedder-Policy", "require-corp");
  next();
});

app.use(cors());
app.use(express.json());
app.use(express.text({ type: '*/*' }));

// Load or create persistent salt for IP hashing
const saltPath = path.join(__dirname, 'ip_salt.txt');
let ipSalt = null;
try {
  ipSalt = fs.readFileSync(saltPath, 'utf8');
} catch (e) {
  ipSalt = crypto.randomBytes(16).toString('hex');
  try { fs.writeFileSync(saltPath, ipSalt); } catch (e) { console.error('Failed to write ip_salt:', e); }
}

function hashIp(ip) {
  return crypto.createHash('sha256').update(ipSalt + '|' + ip).digest('hex');
}

// Simple admin auth middleware (Basic). Set ADMIN_PASSWORD env var to protect admin.
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin';
const authFailures = new Map(); // ip -> {count, blockedUntil}
function adminAuth(req, res, next) {
  const now = Date.now();
  const ip = (req.headers['x-forwarded-for'] || req.connection.remoteAddress || req.ip || '').toString().replace('::ffff:', '');
  const fail = authFailures.get(ip) || { count: 0, blockedUntil: 0 };
  if (fail.blockedUntil && fail.blockedUntil > now) return res.status(429).send('Too many attempts. Try later.');
  const auth = req.headers.authorization || '';
  if (!auth.startsWith('Basic ')) {
    res.setHeader('WWW-Authenticate', 'Basic realm="Admin"');
    return res.status(401).send('Authentication required');
  }
  const creds = Buffer.from(auth.slice(6), 'base64').toString('utf8');
  const [user, pass] = creds.split(':');
  // constant-time compare
  const ok = user === ADMIN_USER && crypto.timingSafeEqual(Buffer.from(pass || ''), Buffer.from(ADMIN_PASSWORD));
  if (!ok) {
    fail.count = (fail.count || 0) + 1;
    if (fail.count > 5) { fail.blockedUntil = now + 5 * 60 * 1000; }
    authFailures.set(ip, fail);
    res.setHeader('WWW-Authenticate', 'Basic realm="Admin"');
    return res.status(401).send('Invalid credentials');
  }
  // reset failures on success
  authFailures.delete(ip);
  next();
}

// SSRF protections helper
function isPrivateIp(ip) {
  if (!ip) return true;
  if (net.isIP(ip) === 0) return true;
  // IPv4 checks
  if (ip.startsWith('127.') || ip === '::1') return true;
  if (ip.startsWith('10.') || ip.startsWith('192.168.')) return true;
  if (/^172\.(1[6-9]|2\d|3[0-1])\./.test(ip)) return true;
  // IPv6 ULA fc00::/7 and link-local fe80::/10
  if (ip.startsWith('fc') || ip.startsWith('fd') || ip.startsWith('fe80') || ip.startsWith('::1')) return true;
  return false;
}

// Restrict requests to localhost only (127.0.0.1, ::1)
function isLocalRequest(req) {
  const ip = (req.headers['x-forwarded-for'] || req.connection.remoteAddress || req.ip || '').toString();
  const clean = ip.replace('::ffff:', '').split(',')[0].trim();
  return clean === '127.0.0.1' || clean === '::1' || clean === '::ffff:127.0.0.1';
}

function requireLocal(req, res, next) {
  if (isLocalRequest(req)) return next();
  res.status(403).send('Admin access restricted to localhost');
}

// Serve the front-end (index.html at project root)
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Multer in-memory upload
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 500 * 1024 * 1024 } });

// Append anonymized session logs to user_logs.txt
app.post('/api/log-session', (req, res) => {
  let payload = req.body;
  if (typeof payload === 'string') {
    try { payload = JSON.parse(payload); } catch (e) { payload = { raw: payload }; }
  }
  const entry = {
    timestamp: new Date().toISOString(),
    type: 'session',
    data: payload
  };
  const logLine = JSON.stringify(entry) + '\n';
  fs.appendFile(path.join(__dirname, 'user_logs.txt'), logLine, (err) => {
    if (err) console.error('Failed to write session log:', err);
  });
  res.status(200).json({ status: 'success' });
});

// Advanced session logging: aggregate by IP in stats.json
app.post('/api/log-session-advanced', async (req, res) => {
  let payload = req.body;
  if (typeof payload === 'string') {
    try { payload = JSON.parse(payload); } catch (e) { payload = { raw: payload }; }
  }
  const ip = (req.headers['x-forwarded-for'] || req.connection.remoteAddress || req.ip || '').toString();
  const clientIp = ip.replace('::ffff:', '');
  const clientHash = hashIp(clientIp);

  const sessionRecord = {
    sessionId: payload.sessionId || null,
    entryTime: payload.entryTime || null,
    exitTime: payload.exitTime || null,
    durationSeconds: Number(payload.durationSeconds || 0),
    filesConverted: Number(payload.filesConverted || 0)
  };

  // Append to raw logs as well
  const entry = { timestamp: new Date().toISOString(), type: 'session-advanced', ipHash: clientHash, data: sessionRecord };
  try {
    await fs.promises.appendFile(path.join(__dirname, 'user_logs.txt'), JSON.stringify(entry) + '\n');
  } catch (e) { console.error('Failed to append advanced log:', e); }

  // Update stats.json
  const statsPath = path.join(__dirname, 'stats.json');
  let stats = { totalTimeSeconds: 0, totalUsers: 0, users: {} };
  try {
    const raw = await fs.promises.readFile(statsPath, 'utf8');
    stats = JSON.parse(raw);
  } catch (e) {
    // ignore, will create fresh
  }

  if (!stats.users) stats.users = {};
  if (!stats.users[clientHash]) {
    stats.users[clientHash] = { totalTimeSeconds: 0, sessions: [] };
  }
  stats.users[clientHash].sessions.push(sessionRecord);
  stats.users[clientHash].totalTimeSeconds += sessionRecord.durationSeconds;

  // Recompute totals
  stats.totalTimeSeconds = Object.values(stats.users).reduce((s, u) => s + (u.totalTimeSeconds || 0), 0);
  stats.totalUsers = Object.keys(stats.users).length;

  try {
    await fs.promises.writeFile(statsPath, JSON.stringify(stats, null, 2));
  } catch (e) { console.error('Failed to write stats.json:', e); }

  res.status(200).json({ status: 'ok', ipHash: clientHash });
});

// Record anonymous rating: { userId, sessionId, rating }
app.post('/api/rating', (req, res) => {
  let payload = req.body;
  if (typeof payload === 'string') {
    try { payload = JSON.parse(payload); } catch (e) { payload = { raw: payload }; }
  }
  const entry = {
    timestamp: new Date().toISOString(),
    type: 'rating',
    data: payload
  };
  const logLine = JSON.stringify(entry) + '\n';
  fs.appendFile(path.join(__dirname, 'ratings.txt'), logLine, (err) => {
    if (err) console.error('Failed to write rating:', err);
  });
  res.status(200).json({ status: 'ok' });
});

// Expose aggregated stats (admin view)
app.get('/api/stats', requireLocal, async (req, res) => {
  const statsPath = path.join(__dirname, 'stats.json');
  try {
    const raw = await fs.promises.readFile(statsPath, 'utf8');
    const stats = JSON.parse(raw);
    res.json(stats);
  } catch (e) {
    res.json({ totalTimeSeconds: 0, totalUsers: 0, users: {} });
  }
});

// Serve a simple admin page
app.get('/admin', requireLocal, (req, res) => {
  res.sendFile(path.join(__dirname, 'admin.html'));
});

// Generic conversion endpoint. Accepts multipart/form-data `file` and query `target` (e.g. target=mp3 or target=gif or target=mp4)
app.post('/api/convert', upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).send('No file uploaded');
  const target = (req.query.target || '').toString().toLowerCase();
  if (!target) return res.status(400).send('No target format specified. Use ?target=mp3|gif|mp4|webm etc.');

  const id = uuidv4();
  const inputName = `${id}-in-${req.file.originalname}`;
  const inputPath = path.join(os.tmpdir(), inputName);
  const outputExt = target.startsWith('.') ? target.slice(1) : target;
  const outputPath = path.join(os.tmpdir(), `${id}-out.${outputExt}`);

  try {
    await fs.promises.writeFile(inputPath, req.file.buffer);

    let command = ffmpeg(inputPath).output(outputPath);

    if (['mp3', 'aac', 'wav', 'm4a', 'ogg'].includes(outputExt)) {
      command = command.noVideo().audioCodec('libmp3lame').audioBitrate('192k');
    } else if (outputExt === 'gif') {
      command = command.outputOptions(['-vf', 'fps=12,scale=640:-1:flags=lanczos']).outputOptions('-gifflags +transdiff');
    } else if (['mp4', 'mov', 'webm', 'mkv'].includes(outputExt)) {
      command = command.videoCodec('libx264').audioCodec('aac').outputOptions(['-preset', 'veryfast']);
    }

    command
      .on('end', async () => {
        res.download(outputPath, `converted.${outputExt}`, async (err) => {
          try { await fs.promises.unlink(inputPath); } catch (e) {}
          try { await fs.promises.unlink(outputPath); } catch (e) {}
        });
      })
      .on('error', async (err) => {
        try { await fs.promises.unlink(inputPath); } catch (e) {}
        try { await fs.promises.unlink(outputPath); } catch (e) {}
        res.status(500).send('Conversion failed: ' + err.message);
      })
      .run();

  } catch (err) {
    try { await fs.promises.unlink(inputPath); } catch (e) {}
    res.status(500).send('Server error: ' + err.message);
  }
});

app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});

// Convert by remote URL: POST JSON { url: string, target: string }
app.post('/api/convert-url', async (req, res) => {
  const { url, target } = req.body || {};
  if (!url) return res.status(400).send('No URL provided');
  if (!target) return res.status(400).send('No target format specified');

  const id = uuidv4();
  const inputPath = path.join(os.tmpdir(), `${id}-in`);
  const outputExt = target.startsWith('.') ? target.slice(1) : target;
  const outputPath = path.join(os.tmpdir(), `${id}-out.${outputExt}`);

  // Helper to download the remote file into inputPath
  const downloadToFile = (remoteUrl, dest) => new Promise((resolve, reject) => {
    (async () => {
      try {
        const parsed = new URL(remoteUrl);
        if (!['http:', 'https:'].includes(parsed.protocol)) return reject(new Error('Only http/https supported'));
        // Resolve DNS and check IPs
        const records = await dns.promises.lookup(parsed.hostname, { all: true });
        for (const r of records) {
          if (isPrivateIp(r.address)) return reject(new Error('URL resolves to a private or disallowed IP'));
        }

        const lib = parsed.protocol === 'https:' ? require('https') : require('http');
        const opts = { headers: { 'User-Agent': 'OmniConvert/1.0' }, timeout: 20000 };
        const req = lib.get(parsed, opts, (response) => {
          if (response.statusCode >= 400) return reject(new Error('Failed to download: ' + response.statusCode));
          // limit size
          const MAX_BYTES = 200 * 1024 * 1024; // 200MB
          let received = 0;
          const fileStream = fs.createWriteStream(dest);
          response.on('data', (chunk) => {
            received += chunk.length;
            if (received > MAX_BYTES) {
              req.destroy();
              fileStream.destroy();
              try { fs.unlinkSync(dest); } catch (e) {}
              return reject(new Error('Remote file too large'));
            }
          });
          response.pipe(fileStream);
          fileStream.on('finish', () => fileStream.close(resolve));
          fileStream.on('error', (err) => { try { fs.unlinkSync(dest); } catch (e){}; reject(err); });
        });
        req.on('error', reject);
        req.setTimeout(30000, () => { req.destroy(); reject(new Error('Download timed out')); });
      } catch (err) { reject(err); }
    })();
  });

  try {
    await downloadToFile(url, inputPath);

    let command = ffmpeg(inputPath).output(outputPath);
    if (['mp3', 'aac', 'wav', 'm4a', 'ogg'].includes(outputExt)) {
      command = command.noVideo().audioCodec('libmp3lame').audioBitrate('192k');
    } else if (outputExt === 'gif') {
      command = command.outputOptions(['-vf', 'fps=12,scale=640:-1:flags=lanczos']).outputOptions('-gifflags +transdiff');
    } else if (['mp4', 'mov', 'webm', 'mkv'].includes(outputExt)) {
      command = command.videoCodec('libx264').audioCodec('aac').outputOptions(['-preset', 'veryfast']);
    }

    command
      .on('end', async () => {
        res.download(outputPath, `converted.${outputExt}`, async (err) => {
          try { await fs.promises.unlink(inputPath); } catch (e) {}
          try { await fs.promises.unlink(outputPath); } catch (e) {}
        });
      })
      .on('error', async (err) => {
        try { await fs.promises.unlink(inputPath); } catch (e) {}
        try { await fs.promises.unlink(outputPath); } catch (e) {}
        res.status(500).send('Conversion failed: ' + err.message);
      })
      .run();

  } catch (err) {
    try { await fs.promises.unlink(inputPath); } catch (e) {}
    res.status(500).send('Server error: ' + err.message);
  }
});