Ton `server.js` utilise encore `better-sqlite3` partout mais ton `package.json` ne l'a plus. Il faut **tout convertir en MongoDB**. Voici ton `server.js` complet corrigé :

```javascript
const express = require('express');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { MongoClient, ObjectId } = require('mongodb');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const SECRET = 'cidemo_secret_key_2025';
const MONGO_URI = process.env.MONGO_URI || 'mongodb+srv://user:pass@cluster.mongodb.net/cidemo';

let db;

async function start() {
  const client = await MongoClient.connect(MONGO_URI);
  db = client.db();
  console.log('✅ MongoDB connecté');

  // Créer admin par défaut s'il n'existe pas
  const adminExists = await db.collection('users').findOne({ role: 'admin' });
  if (!adminExists) {
    const hash = bcrypt.hashSync('admin123', 10);
    await db.collection('users').insertOne({
      nom: 'Admin CiDemo',
      email: 'admin@cidemo.com',
      password: hash,
      role: 'admin',
      created_at: new Date()
    });
    console.log('Admin créé : admin@cidemo.com / admin123');
  }

  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => console.log(`CiDemo API sur port ${PORT}`));
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
app.post('/api/register', async (req, res) => {
  try {
    const { nom, email, password } = req.body;
    if (!nom || !email || !password) return res.status(400).json({ error: 'Champs requis' });
    if (password.length < 6) return res.status(400).json({ error: 'Mot de passe min 6 caractères' });

    const exists = await db.collection('users').findOne({ email });
    if (exists) return res.status(400).json({ error: 'Email déjà utilisé' });

    const hash = bcrypt.hashSync(password, 10);
    const result = await db.collection('users').insertOne({ nom, email, password: hash, role: 'client', created_at: new Date() });

    const token = jwt.sign({ id: result.insertedId, email, role: 'client', nom }, SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: result.insertedId, nom, email, role: 'client' } });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Champs requis' });

    const user = await db.collection('users').findOne({ email });
    if (!user) return res.status(400).json({ error: 'Email non trouvé' });

    if (!bcrypt.compareSync(password, user.password)) return res.status(400).json({ error: 'Mot de passe incorrect' });

    const token = jwt.sign({ id: user._id, email: user.email, role: user.role, nom: user.nom }, SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user._id, nom: user.nom, email: user.email, role: user.role } });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/me', authMiddleware, async (req, res) => {
  try {
    const user = await db.collection('users').findOne({ _id: new ObjectId(req.user.id) }, { projection: { password: 0 } });
    if (!user) return res.status(404).json({ error: 'Utilisateur non trouvé' });
    res.json({ user });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ===== ROUTES ADMIN =====
app.get('/api/users', authMiddleware, adminOnly, async (req, res) => {
  try {
    const users = await db.collection('users').find({}, { projection: { password: 0 } }).sort({ created_at: -1 }).toArray();
    res.json({ users });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/users', authMiddleware, adminOnly, async (req, res) => {
  try {
    const { nom, email, password, role } = req.body;
    if (!nom || !email || !password) return res.status(400).json({ error: 'Champs requis' });

    const exists = await db.collection('users').findOne({ email });
    if (exists) return res.status(400).json({ error: 'Email déjà utilisé' });

    const hash = bcrypt.hashSync(password, 10);
    const result = await db.collection('users').insertOne({ nom, email, password: hash, role: role || 'client', created_at: new Date() });
    res.json({ success: true, id: result.insertedId });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.delete('/api/users/:id', authMiddleware, adminOnly, async (req, res) => {
  try {
    if (req.user.id === req.params.id) return res.status(400).json({ error: 'Tu ne peux pas te supprimer toi-même' });
    await db.collection('users').deleteOne({ _id: new ObjectId(req.params.id) });
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ===== ROUTE CRÉATION ADMIN PERSO =====
app.get('/create-admin', async (req, res) => {
  try {
    const hash = await bcrypt.hash('Tr1st@nDUCOURTYpro', 10);
    await db.collection('users').insertOne({
      nom: 'Tristan Ducourty',
      email: 'tristanducourtypro@gmail.com',
      password: hash,
      role: 'admin',
      created_at: new Date()
    });
    res.send('✅ Compte admin créé !');
  } catch (e) {
    res.send('❌ Erreur : ' + e.message);
  }
});

start().catch(err => console.error('❌ Erreur démarrage :', err));
```

**Ensuite sur Render**, ajoute la variable d'environnement :
- **Clé** : `MONGO_URI`
- **Valeur** : ton URI MongoDB Atlas (celle que tu as déjà)

Puis redéploie.
