const sqlite3 = require('better-sqlite3');
const bcrypt = require('bcrypt');
const path = require('path');

const db = new sqlite3(path.join(__dirname, 'platform.db'));

// Récupérer les arguments : node seed.js <username> <password>
const [,, username, password] = process.argv;

if (!username || !password) {
  console.log('Usage: node seed.js <username> <password>');
  console.log('Exemple: node seed.js admin MonMotDePasse123');
  process.exit(1);
}

if (password.length < 6) {
  console.error('Erreur : le mot de passe doit faire au moins 6 caractères');
  process.exit(1);
}

(async () => {
  try {
    // Créer les tables si elles n'existent pas
    db.exec(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE,
        password TEXT,
        role TEXT DEFAULT 'user',
        created_at INTEGER,
        created_by INTEGER
      );
    `);

    // Vérifier si un admin existe déjà
    const existing = db.prepare("SELECT id, username FROM users WHERE role = 'admin'").get();
    if (existing) {
      console.log(`Un administrateur existe déjà : "${existing.username}"`);
      console.log('Pour créer un autre admin, connectez-vous et utilisez le panneau d\'administration.');
      process.exit(0);
    }

    // Créer l'admin
    const hash = await bcrypt.hash(password, 10);
    const info = db.prepare(
      'INSERT INTO users (username, password, role, created_at) VALUES (?, ?, ?, ?)'
    ).run(username, hash, 'admin', Date.now());

    console.log('✅ Administrateur créé avec succès :');
    console.log(`   ID       : ${info.lastInsertRowid}`);
    console.log(`   Username : ${username}`);
    console.log(`   Rôle     : admin`);
    console.log('');
    console.log('Connectez-vous sur la plateforme avec ces identifiants.');
  } catch (e) {
    console.error('Erreur :', e.message);
    process.exit(1);
  }
})();