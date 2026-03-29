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

// Créer un admin par défaut s'il n'existe pas
const adminExists = db.prepare('SELECT id FROM users WHERE role = ?').get('admin');
if (!adminExists) {
  const hash = bcrypt.hashSync('admin123', 10);
  db.prepare('INSERT INTO users (nom, email, password, role) VALUES (?, ?, ?, ?)').run('Admin CiDemo', 'admin@cidemo.com', hash, 'admin');
  console.log('Admin créé : admin@cidemo.com / admin123');
}

// ===== MIDDLEWARE AUTH =====
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

// ===== ROUTES AUTH =====
app.post('/api/register', (req, res) => {
  const { nom, email, password } = req.body;
  if (!nom || !email || !password) return res.status(400).json({ error: 'Champs requis' });
  if (password.length < 6) return res.status(400).json({ error: 'Mot de passe min 6 caractères' });

  const exists = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
  if (exists) return res.status(400).json({ error: 'Email déjà utilisé' });

  const hash = bcrypt.hashSync(password, 10);
  const result = db.prepare('INSERT INTO users (nom, email, password, role) VALUES (?, ?, ?, ?)').run(nom, email, hash, 'client');

  const token = jwt.sign({ id: result.lastInsertRowid, email, role: 'client', nom }, SECRET, { expiresIn: '7d' });
  res.json({ token, user: { id: result.lastInsertRowid, nom, email, role: 'client' } });
});

app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Champs requis' });

  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (!user) return res.status(400).json({ error: 'Email non trouvé' });

  if (!bcrypt.compareSync(password, user.password)) return res.status(400).json({ error: 'Mot de passe incorrect' });

  const token = jwt.sign({ id: user.id, email: user.email, role: user.role, nom: user.nom }, SECRET, { expiresIn: '7d' });
  res.json({ token, user: { id: user.id, nom: user.nom, email: user.email, role: user.role } });
});

app.get('/api/me', authMiddleware, (req, res) => {
  const user = db.prepare('SELECT id, nom, email, role, created_at FROM users WHERE id = ?').get(req.user.id);
  if (!user) return res.status(404).json({ error: 'Utilisateur non trouvé' });
  res.json({ user });
});

// ===== ROUTES ADMIN =====
app.get('/api/users', authMiddleware, adminOnly, (req, res) => {
  const users = db.prepare('SELECT id, nom, email, role, created_at FROM users ORDER BY created_at DESC').all();
  res.json({ users });
});

app.post('/api/users', authMiddleware, adminOnly, (req, res) => {
  const { nom, email, password, role } = req.body;
  if (!nom || !email || !password) return res.status(400).json({ error: 'Champs requis' });

  const exists = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
  if (exists) return res.status(400).json({ error: 'Email déjà utilisé' });

  const hash = bcrypt.hashSync(password, 10);
  const result = db.prepare('INSERT INTO users (nom, email, password, role) VALUES (?, ?, ?, ?)').run(nom, email, hash, role || 'client');
  res.json({ success: true, id: result.lastInsertRowid });
});

app.delete('/api/users/:id', authMiddleware, adminOnly, (req, res) => {
  if (req.user.id === parseInt(req.params.id)) return res.status(400).json({ error: 'Tu ne peux pas te supprimer toi-même' });
  db.prepare('DELETE FROM users WHERE id = ?').run(req.params.id);
  res.json({ success: true });
});

// ===== DÉMARRAGE =====
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`CiDemo API sur port ${PORT}`));

// Route temporaire pour créer un admin
app.get('/create-admin', async (req, res) => {
  try {
    const bcrypt = require('bcryptjs');
    const hash = await bcrypt.hash('Tr1st@nDUCOURTYpro', 10);
    await mongoose.connection.db.collection('users').insertOne({
      nom: 'Tristan Ducourty',
      email: 'tristanducourtypro@gmail.com',
      password: hash
    });
    res.send('✅ Compte admin créé !');
  } catch(e) {
    res.send('❌ Erreur : ' + e.message);
  }
});
