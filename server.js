const express = require('express');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Database = require('better-sqlite3');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const SECRET = 'cidemo_secret_key_2025';
const db = new Database('cidemo.db');

// ===== CRÉATION DES TABLES =====
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nom TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT DEFAULT 'client',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )
`);

// ===== ADMIN PAR DÉFAUT =====
const adminExists = db.prepare("SELECT id FROM users WHERE role = 'admin'").get();
if (!adminExists) {
  const hash = bcrypt.hashSync('admin123', 10);
  db.prepare("INSERT INTO users (nom, email, password, role) VALUES (?, ?, ?, 'admin')")
    .run('Admin CiDemo', 'admin@cidemo.com', hash);
  console.log('Admin créé : admin@cidemo.com / admin123');
}

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

// ===== ROUTES =====
app.post('/api/register', (req, res) => {
  try {
    const { nom, email, password } = req.body;
    if (!nom || !email || !password) return res.status(400).json({ error: 'Champs requis' });
    if (password.length < 6) return res.status(400).json({ error: 'Mot de passe min 6 caractères' });
    const exists = db.prepare("SELECT id FROM users WHERE email = ?").get(email);
    if (exists) return res.status(400).json({ error: 'Email déjà utilisé' });
    const hash = bcrypt.hashSync(password, 10);
    const result = db.prepare("INSERT INTO users (nom, email, password, role) VALUES (?, ?, ?, 'client')")
      .run(nom, email, hash);
    const token = jwt.sign({ id: result.lastInsertRowid, email, role: 'client', nom }, SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: result.lastInsertRowid, nom, email, role: 'client' } });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/login', (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Champs requis' });
    const user = db.prepare("SELECT * FROM users WHERE email = ?").get(email);
    if (!user) return res.status(400).json({ error: 'Email non trouvé' });
    if (!bcrypt.compareSync(password, user.password)) return res.status(400).json({ error: 'Mot de passe incorrect' });
    const token = jwt.sign({ id: user.id, email: user.email, role: user.role, nom: user.nom }, SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user.id, nom: user.nom, email: user.email, role: user.role } });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/me', authMiddleware, (req, res) => {
  try {
    const user = db.prepare("SELECT id, nom, email, role, created_at FROM users WHERE id = ?").get(req.user.id);
    if (!user) return res.status(404).json({ error: 'Utilisateur non trouvé' });
    res.json({ user });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/users', authMiddleware, adminOnly, (req, res) => {
  try {
    const users = db.prepare("SELECT id, nom, email, role, created_at FROM users ORDER BY created_at DESC").all();
    res.json({ users });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/users', authMiddleware, adminOnly, (req, res) => {
  try {
    const { nom, email, password, role } = req.body;
    if (!nom || !email || !password) return res.status(400).json({ error: 'Champs requis' });
    const exists = db.prepare("SELECT id FROM users WHERE email = ?").get(email);
    if (exists) return res.status(400).json({ error: 'Email déjà utilisé' });
    const hash = bcrypt.hashSync(password, 10);
    const result = db.prepare("INSERT INTO users (nom, email, password, role) VALUES (?, ?, ?, ?)")
      .run(nom, email, hash, role || 'client');
    res.json({ success: true, id: result.lastInsertRowid });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.delete('/api/users/:id', authMiddleware, adminOnly, (req, res) => {
  try {
    if (req.user.id == req.params.id) return res.status(400).json({ error: 'Tu ne peux pas te supprimer toi-même' });
    db.prepare("DELETE FROM users WHERE id = ?").run(req.params.id);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/create-admin', (req, res) => {
  try {
    const hash = bcrypt.hashSync('Tr1st@nDUCOURTYpro', 10);
    db.prepare("INSERT INTO users (nom, email, password, role) VALUES (?, ?, ?, 'admin')")
      .run('Tristan Ducourty', 'tristanducourtypro@gmail.com', hash);
    res.send('✅ Compte admin créé !');
  } catch (e) {
    res.send('❌ Erreur : ' + e.message);
  }
});
// ===== CRÉATION DES TABLES =====
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nom TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT DEFAULT 'client',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )
`);

// Ajout des nouvelles tables
db.exec(`
  CREATE TABLE IF NOT EXISTS prospects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    type TEXT NOT NULL,
    canal TEXT,
    status TEXT NOT NULL,
    notes TEXT,
    date TEXT,
    user_id INTEGER,
    FOREIGN KEY(user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS activities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    text TEXT NOT NULL,
    date TEXT,
    FOREIGN KEY(user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS calls (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    prospect_id INTEGER,
    type TEXT NOT NULL,
    date TEXT,
    result TEXT,
    notes TEXT,
    FOREIGN KEY(prospect_id) REFERENCES prospects(id)
  );
`);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`CiDemo API sur port ${PORT}`));
