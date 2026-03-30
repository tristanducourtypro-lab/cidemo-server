const express = require('express');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const SECRET = 'cidemo_secret_key_2025';
const pool = new Pool({ connectionString: process.env.DATABASE_URL });

async function query(text, params) {
  const result = await pool.query(text, params);
  return result;
}

// ===== INIT DB =====
async function initDB() {
  await query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      nom TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT DEFAULT 'client',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS prospects (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      type TEXT NOT NULL,
      canal TEXT,
      status TEXT NOT NULL,
      notes TEXT,
      date TEXT,
      user_id INTEGER REFERENCES users(id)
    )
  `);

  await query(`ALTER TABLE prospects ADD COLUMN IF NOT EXISTS fathom TEXT`);

  await query(`
    CREATE TABLE IF NOT EXISTS activities (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id),
      text TEXT NOT NULL,
      date TEXT
    )
  `);

  await query(`
    CREATE TABLE IF NOT EXISTS calls (
      id SERIAL PRIMARY KEY,
      prospect_id INTEGER REFERENCES prospects(id),
      type TEXT NOT NULL,
      date TEXT,
      result TEXT,
      notes TEXT
    )
  `);

  const adminCheck = await query("SELECT id FROM users WHERE role = 'admin' LIMIT 1");
  if (adminCheck.rows.length === 0) {
    const hash = bcrypt.hashSync('admin123', 10);
    await query("INSERT INTO users (nom, email, password, role) VALUES ($1, $2, $3, 'admin')",
      ['Admin CiDemo', 'admin@cidemo.com', hash]);
    console.log('Admin créé : admin@cidemo.com / admin123');
  }

  console.log('Base de données prête');
}

initDB().catch(err => console.error('Erreur init DB:', err.message));

// ===== MIDDLEWARES =====
function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Non connecté' });
  try {
    req.user = jwt.verify(token, SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Token invalide' });
  }
}

function adminOnly(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Accès refusé' });
  next();
}

// ===== AUTH =====
app.post('/api/register', async (req, res) => {
  try {
    const { nom, email, password } = req.body;
    if (!nom || !email || !password) return res.status(400).json({ error: 'Champs requis' });
    if (password.length < 6) return res.status(400).json({ error: 'Mot de passe min 6 caractères' });
    const exists = await query("SELECT id FROM users WHERE email = $1", [email]);
    if (exists.rows.length > 0) return res.status(400).json({ error: 'Email déjà utilisé' });
    const hash = bcrypt.hashSync(password, 10);
    const result = await query("INSERT INTO users (nom, email, password, role) VALUES ($1, $2, $3, 'client') RETURNING id",
      [nom, email, hash]);
    const id = result.rows[0].id;
    const token = jwt.sign({ id, email, role: 'client', nom }, SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id, nom, email, role: 'client' } });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Champs requis' });
    const result = await query("SELECT * FROM users WHERE email = $1", [email]);
    const user = result.rows[0];
    if (!user) return res.status(400).json({ error: 'Email non trouvé' });
    if (!bcrypt.compareSync(password, user.password)) return res.status(400).json({ error: 'Mot de passe incorrect' });
    const token = jwt.sign({ id: user.id, email: user.email, role: user.role, nom: user.nom }, SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user.id, nom: user.nom, email: user.email, role: user.role } });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/me', authMiddleware, async (req, res) => {
  try {
    const result = await query("SELECT id, nom, email, role, created_at FROM users WHERE id = $1", [req.user.id]);
    const user = result.rows[0];
    if (!user) return res.status(404).json({ error: 'Utilisateur non trouvé' });
    res.json({ user });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ===== USERS (admin) =====
app.get('/api/users', authMiddleware, adminOnly, async (req, res) => {
  try {
    const result = await query("SELECT id, nom, email, role, created_at FROM users ORDER BY created_at DESC");
    res.json({ users: result.rows });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/users', authMiddleware, adminOnly, async (req, res) => {
  try {
    const { nom, email, password, role } = req.body;
    if (!nom || !email || !password) return res.status(400).json({ error: 'Champs requis' });
    const exists = await query("SELECT id FROM users WHERE email = $1", [email]);
    if (exists.rows.length > 0) return res.status(400).json({ error: 'Email déjà utilisé' });
    const hash = bcrypt.hashSync(password, 10);
    const result = await query("INSERT INTO users (nom, email, password, role) VALUES ($1, $2, $3, $4) RETURNING id",
      [nom, email, hash, role || 'client']);
    res.json({ success: true, id: result.rows[0].id });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.delete('/api/users/:id', authMiddleware, adminOnly, async (req, res) => {
  try {
    if (req.user.id == req.params.id) return res.status(400).json({ error: 'Tu ne peux pas te supprimer toi-même' });
    await query("DELETE FROM users WHERE id = $1", [req.params.id]);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/create-admin', async (req, res) => {
  try {
    const hash = bcrypt.hashSync('Tr1st@nDUCOURTYpro', 10);
    await query("INSERT INTO users (nom, email, password, role) VALUES ($1, $2, $3, 'admin')",
      ['Tristan Ducourty', 'tristanducourtypro@gmail.com', hash]);
    res.send('✅ Compte admin créé !');
  } catch (e) {
    res.send('❌ Erreur : ' + e.message);
  }
});

// ===== PROSPECTS =====
app.get('/api/prospects', authMiddleware, async (req, res) => {
  try {
    const result = await query("SELECT * FROM prospects WHERE user_id = $1 ORDER BY id DESC", [req.user.id]);
    res.json(result.rows);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/prospects', authMiddleware, async (req, res) => {
  try {
    const { name, type, canal, status, notes, fathom } = req.body;
    if (!name || !type) return res.status(400).json({ error: 'Nom et type requis' });
    const date = new Date().toLocaleDateString('fr-FR');
    const result = await query(
      "INSERT INTO prospects (name, type, canal, status, notes, fathom, date, user_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *",
      [name, type, canal || '', status || 'contacte', notes || '', fathom || '', date, req.user.id]
    );
    await query("INSERT INTO activities (user_id, text, date) VALUES ($1, $2, $3)",
      [req.user.id, `${name} ajouté en tant que prospect`, date]);
    res.json({ success: true, prospect: result.rows[0] });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.put('/api/prospects/:id', authMiddleware, async (req, res) => {
  try {
    const { status, notes, fathom } = req.body;
    const result = await query(
      "UPDATE prospects SET status = $1, notes = COALESCE($2, notes), fathom = $3 WHERE id = $4 AND user_id = $5 RETURNING *",
      [status, notes, fathom, req.params.id, req.user.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Prospect non trouvé' });
    const p = result.rows[0];
    await query("INSERT INTO activities (user_id, text, date) VALUES ($1, $2, $3)",
      [req.user.id, `${p.name} passé en ${status}`, new Date().toLocaleDateString('fr-FR')]);
    res.json({ success: true, prospect: p });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.delete('/api/prospects/:id', authMiddleware, async (req, res) => {
  try {
    await query("DELETE FROM prospects WHERE id = $1 AND user_id = $2", [req.params.id, req.user.id]);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ===== ACTIVITIES =====
app.get('/api/activities', authMiddleware, async (req, res) => {
  try {
    const result = await query(
      "SELECT * FROM activities WHERE user_id = $1 ORDER BY id DESC LIMIT 50",
      [req.user.id]
    );
    res.json(result.rows);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ===== START =====
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`CiDemo API sur port ${PORT}`));
