const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const os = require('os');
const { spawn } = require('child_process');
const { DatabaseSync } = require('node:sqlite');

// ── Config ──
const JWT_SECRET = process.env.JWT_SECRET || 'foodmap-secret-' + Math.random().toString(36).slice(2);
const JWT_EXPIRES = '30d';
const UPLOADS_DIR = path.join(__dirname, 'uploads');
const DATA_DIR = path.join(__dirname, 'data');
const DB_PATH = path.join(DATA_DIR, 'foodmap.db');

// Ensure directories
[UPLOADS_DIR, DATA_DIR].forEach(d => { if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true }); });

// ── Database ──
const db = new DatabaseSync(DB_PATH);
db.exec('PRAGMA journal_mode = WAL');
db.exec('PRAGMA foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000)
  );
  CREATE TABLE IF NOT EXISTS foods (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    username TEXT NOT NULL,
    name TEXT NOT NULL,
    category TEXT DEFAULT '',
    rating INTEGER DEFAULT 0,
    description TEXT DEFAULT '',
    lat REAL NOT NULL,
    lng REAL NOT NULL,
    photo TEXT DEFAULT '',
    created_at INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000),
    updated_at INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );
`);
try { db.exec('CREATE INDEX IF NOT EXISTS idx_foods_user ON foods(user_id)'); } catch {}
try { db.exec('CREATE INDEX IF NOT EXISTS idx_foods_created ON foods(created_at DESC)'); } catch {}

// ── Multer ──
const storage = multer.diskStorage({
  destination: UPLOADS_DIR,
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase() || '.jpg';
    cb(null, `img_${Date.now()}_${Math.random().toString(36).slice(2, 6)}${ext}`);
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) cb(null, true);
    else cb(new Error('只允许上传图片文件'));
  }
});

// ── Express ──
const app = express();
app.use(cors());
app.use(express.json({ limit: '2mb' }));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/api/photos', express.static(UPLOADS_DIR));

// ── Middleware ──
function requireAuth(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) {
    return res.status(401).json({ error: '请先登录' });
  }
  try {
    req.user = jwt.verify(header.split(' ')[1], JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: '登录已过期，请重新登录' });
  }
}

function optionalAuth(req, res, next) {
  const header = req.headers.authorization;
  if (header && header.startsWith('Bearer ')) {
    try { req.user = jwt.verify(header.split(' ')[1], JWT_SECRET); } catch {}
  }
  next();
}

// ── Helper: run a query and return rows (node:sqlite API) ──
function queryAll(sql, ...params) {
  const stmt = db.prepare(sql);
  return params.length ? stmt.all(...params) : stmt.all();
}
function queryOne(sql, ...params) {
  const stmt = db.prepare(sql);
  return params.length ? stmt.get(...params) : stmt.get();
}
function exec(sql, ...params) {
  const stmt = db.prepare(sql);
  return params.length ? stmt.run(...params) : stmt.run();
}

// ── Auth routes ──

app.post('/api/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: '用户名和密码不能为空' });
    if (username.length < 2 || username.length > 20) return res.status(400).json({ error: '用户名需 2-20 个字符' });
    if (password.length < 4 || password.length > 50) return res.status(400).json({ error: '密码需 4-50 个字符' });
    if (!/^[\w\u4e00-\u9fa5]+$/.test(username)) return res.status(400).json({ error: '用户名只能包含中英文、数字和下划线' });

    // Check duplicate
    const existing = queryOne('SELECT id FROM users WHERE username = ?', username);
    if (existing) return res.status(400).json({ error: '用户名已存在' });

    const hash = await bcrypt.hash(password, 10);
    exec('INSERT INTO users (username, password_hash) VALUES (?, ?)', username, hash);

    // Get inserted ID
    const newUser = queryOne('SELECT id, username FROM users WHERE username = ?', username);
    const token = jwt.sign({ id: newUser.id, username: newUser.username }, JWT_SECRET, { expiresIn: JWT_EXPIRES });
    res.json({ token, user: { id: newUser.id, username: newUser.username } });
  } catch (err) {
    console.error('Register error:', err);
    res.status(500).json({ error: '注册失败，请稍后重试' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: '请输入用户名和密码' });

    const user = queryOne('SELECT id, username, password_hash FROM users WHERE username = ?', username);
    if (!user) return res.status(400).json({ error: '用户名或密码错误' });

    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(400).json({ error: '用户名或密码错误' });

    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: JWT_EXPIRES });
    res.json({ token, user: { id: user.id, username: user.username } });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: '登录失败，请稍后重试' });
  }
});

app.get('/api/me', requireAuth, (req, res) => {
  const user = queryOne('SELECT id, username FROM users WHERE id = ?', req.user.id);
  if (!user) return res.status(401).json({ error: '用户不存在' });
  res.json({ user });
});

// ── Food routes ──

app.get('/api/foods', optionalAuth, (req, res) => {
  try {
    const foods = queryAll('SELECT * FROM foods ORDER BY created_at DESC');
    res.json(foods.map(f => ({ ...f, isOwner: req.user ? f.user_id === req.user.id : false })));
  } catch (err) {
    console.error('Get foods error:', err);
    res.status(500).json({ error: '获取数据失败' });
  }
});

app.post('/api/foods', requireAuth, upload.single('photo'), (req, res) => {
  try {
    const { name, category, rating, description, lat, lng } = req.body;
    if (!name || !name.trim()) return res.status(400).json({ error: '请输入美食名称' });
    const latNum = parseFloat(lat), lngNum = parseFloat(lng);
    if (isNaN(latNum) || isNaN(lngNum) || latNum < -90 || latNum > 90 || lngNum < -180 || lngNum > 180) {
      return res.status(400).json({ error: '坐标无效，请在地图上选择位置' });
    }

    const id = 'f_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2, 6);
    const photoName = req.file ? req.file.filename : '';
    const now = Date.now();

    exec(
      'INSERT INTO foods (id, user_id, username, name, category, rating, description, lat, lng, photo, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
      id, req.user.id, req.user.username, name.trim(), (category || '').trim(),
      Math.min(5, Math.max(0, parseInt(rating) || 0)), (description || '').trim(),
      latNum, lngNum, photoName, now, now
    );

    const food = queryOne('SELECT * FROM foods WHERE id = ?', id);
    res.json({ ...food, isOwner: true });
  } catch (err) {
    console.error('Add food error:', err);
    res.status(500).json({ error: '添加失败' });
  }
});

app.put('/api/foods/:id', requireAuth, upload.single('photo'), (req, res) => {
  try {
    const food = queryOne('SELECT * FROM foods WHERE id = ?', req.params.id);
    if (!food) return res.status(404).json({ error: '记录不存在' });
    if (food.user_id !== req.user.id) return res.status(403).json({ error: '只能编辑自己的美食记录' });

    const { name, category, rating, description, lat, lng } = req.body;
    if (!name || !name.trim()) return res.status(400).json({ error: '请输入美食名称' });
    const latNum = parseFloat(lat), lngNum = parseFloat(lng);
    if (isNaN(latNum) || isNaN(lngNum)) return res.status(400).json({ error: '坐标无效' });

    let photoName = food.photo;
    if (req.file) {
      if (food.photo) {
        try { fs.unlinkSync(path.join(UPLOADS_DIR, food.photo)); } catch {}
      }
      photoName = req.file.filename;
    }

    exec(
      'UPDATE foods SET name=?, category=?, rating=?, description=?, lat=?, lng=?, photo=?, updated_at=? WHERE id=?',
      name.trim(), (category || '').trim(), Math.min(5, Math.max(0, parseInt(rating) || 0)),
      (description || '').trim(), latNum, lngNum, photoName, Date.now(), req.params.id
    );

    const updated = queryOne('SELECT * FROM foods WHERE id = ?', req.params.id);
    res.json({ ...updated, isOwner: true });
  } catch (err) {
    console.error('Update food error:', err);
    res.status(500).json({ error: '更新失败' });
  }
});

app.delete('/api/foods/:id', requireAuth, (req, res) => {
  try {
    const food = queryOne('SELECT * FROM foods WHERE id = ?', req.params.id);
    if (!food) return res.status(404).json({ error: '记录不存在' });
    if (food.user_id !== req.user.id) return res.status(403).json({ error: '只能删除自己的美食记录' });

    if (food.photo) {
      try { fs.unlinkSync(path.join(UPLOADS_DIR, food.photo)); } catch {}
    }
    exec('DELETE FROM foods WHERE id = ?', req.params.id);
    res.json({ success: true });
  } catch (err) {
    console.error('Delete food error:', err);
    res.status(500).json({ error: '删除失败' });
  }
});

// ── Health check ──
app.get('/api/health', (req, res) => {
  const foodCount = queryOne('SELECT COUNT(*) as c FROM foods');
  const userCount = queryOne('SELECT COUNT(*) as c FROM users');
  res.json({ ok: true, foods: foodCount?.c || 0, users: userCount?.c || 0, uptime: Math.floor(process.uptime()) });
});

// ── SPA fallback ──
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ── Error handler ──
app.use((err, req, res, next) => {
  if (err.code === 'LIMIT_FILE_SIZE') return res.status(400).json({ error: '图片不能超过 5MB' });
  console.error('Server error:', err);
  res.status(500).json({ error: '服务器错误' });
});

// ── Start ──
function getLocalIPs() {
  const nets = os.networkInterfaces();
  const ips = [];
  for (const name of Object.keys(nets)) {
    for (const net of nets[name]) {
      if (net.family === 'IPv4' && !net.internal) ips.push(net.address);
    }
  }
  return ips;
}

// 端口: 默认 0 = 系统自动分配随机空闲端口，永不冲突；也可用环境变量 PORT 指定
const listenPort = parseInt(process.env.PORT, 10) || 0;

// ── 公网隧道（Cloudflare 快速隧道，无验证页）──
// cloudflared 二进制可能在 npm install 时下载失败（GitHub 被墙），这里自动修复
function downloadFile(url, dest, timeoutMs) {
  return new Promise((resolve, reject) => {
    const https = require('https');
    const file = fs.createWriteStream(dest);
    let req;
    const timer = setTimeout(() => { req && req.destroy(); file.destroy(); reject(new Error('下载超时')); }, timeoutMs || 60000);
    req = https.get(url, (res) => {
      const redirectCodes = [301, 302, 303, 307, 308];
      if (redirectCodes.includes(res.statusCode) && res.headers.location) {
        file.close(); clearTimeout(timer);
        return resolve(downloadFile(res.headers.location, dest, timeoutMs));
      }
      if (res.statusCode >= 200 && res.statusCode < 300) {
        res.pipe(file);
        file.on('finish', () => { clearTimeout(timer); file.close(() => resolve(dest)); });
      } else {
        clearTimeout(timer); file.destroy(); reject(new Error('HTTP ' + res.statusCode));
      }
    });
    req.on('error', (e) => { clearTimeout(timer); reject(e); });
  });
}

async function ensureCloudflared(cfBin) {
  if (fs.existsSync(cfBin) && fs.statSync(cfBin).size > 1000000) return true;
  fs.mkdirSync(path.dirname(cfBin), { recursive: true });
  const gh = 'https://github.com/cloudflare/cloudflared/releases/latest/download/';
  const mirrors = [gh, 'https://gh-proxy.com/' + gh, 'https://mirror.ghproxy.com/' + gh];
  let file = '';
  if (process.platform === 'win32') file = process.arch === 'ia32' ? 'cloudflared-windows-386.exe' : 'cloudflared-windows-amd64.exe';
  else if (process.platform === 'linux') file = process.arch === 'arm64' ? 'cloudflared-linux-arm64' : 'cloudflared-linux-amd64';
  else return false; // macos 等平台交给 npm 包自身处理
  for (const base of mirrors) {
    try {
      await downloadFile(base + file, cfBin);
      if (fs.existsSync(cfBin) && fs.statSync(cfBin).size > 1000000) {
        if (process.platform !== 'win32') fs.chmodSync(cfBin, 0o755);
        return true;
      }
    } catch {}
    try { fs.unlinkSync(cfBin); } catch {}
  }
  return false;
}

function startTunnel(cfBin, port) {
  const child = spawn(cfBin, ['tunnel', '--url', `http://localhost:${port}`], { stdio: ['ignore', 'pipe', 'pipe'] });
  let output = '';
  const grab = (chunk) => {
    output += chunk.toString();
    const m = output.match(/https:\/\/[a-z0-9-]+\.trycloudflare\.com/);
    if (m && !child._urlPrinted) {
      child._urlPrinted = true;
      console.log(`  🌐 公网访问:  ${m[0]}`);
      console.log('');
      console.log('  按 Ctrl+C 停止服务');
      console.log('');
    }
  };
  child.stdout.on('data', grab);
  child.stderr.on('data', grab);
  child.on('exit', () => console.log('  ⚠️  公网隧道已断开，重启服务可重新连接'));
}

const server = app.listen(listenPort, '0.0.0.0', () => {
  const PORT = server.address().port; // 实际分配到的端口
  const ips = getLocalIPs();
  console.log('');
  console.log('  🍜  美食地图服务已启动！');
  console.log('  ────────────────────────');
  console.log(`  本机访问:  http://localhost:${PORT}`);
  ips.forEach(ip => console.log(`  局域网:    http://${ip}:${PORT}`));
  console.log('');

  // 自动启动公网隧道
  const cfBin = path.join(__dirname, 'node_modules', 'cloudflared', 'bin', process.platform === 'win32' ? 'cloudflared.exe' : 'cloudflared');
  (async () => {
    if (await ensureCloudflared(cfBin)) {
      startTunnel(cfBin, PORT);
    } else {
      console.log('  ⚠️  公网隧道不可用：cloudflared 下载失败（网络限制）');
      console.log('     内网访问不受影响。可手动下载 cloudflared 后重试');
      console.log('');
      console.log('  按 Ctrl+C 停止服务');
      console.log('');
    }
  })();
});
