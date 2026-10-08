#!/usr/bin/env node
/**
 * Script d'initialisation de la base de données SQLite.
 * 
 * Usage :
 *   node init-db.js              → crée la base si elle n'existe pas
 *   node init-db.js --reset      → supprime et recrée (⚠️ efface tout)
 *   node init-db.js --status     → affiche l'état de la base
 */

const fs = require('fs');
const path = require('path');
const sqlite3 = require('better-sqlite3');

const DB_PATH = path.join(__dirname, 'platform.db');
const SCHEMA_PATH = path.join(__dirname, 'schema.sql');

const args = process.argv.slice(2);
const isReset = args.includes('--reset');
const isStatus = args.includes('--status');

console.log('📦 Base de données :', DB_PATH);
console.log('');

// Mode status : afficher l'état actuel
if (isStatus) {
  if (!fs.existsSync(DB_PATH)) {
    console.log('❌ La base de données n\'existe pas.');
    process.exit(0);
  }
  const db = new sqlite3(DB_PATH);
  const stats = {
    users: db.prepare('SELECT COUNT(*) AS c FROM users').get().c,
    admins: db.prepare("SELECT COUNT(*) AS c FROM users WHERE role = 'admin'").get().c,
    progress: db.prepare('SELECT COUNT(*) AS c FROM progress').get().c,
    completed: db.prepare('SELECT COUNT(*) AS c FROM progress WHERE completed = 1').get().c
  };
  console.log('📊 État de la base :');
  console.log(`   Utilisateurs    : ${stats.users}`);
  console.log(`   Admins          : ${stats.admins}`);
  console.log(`   Progressions    : ${stats.progress}`);
  console.log(`   Cours terminés  : ${stats.completed}`);
  console.log('');
  console.log('👥 Utilisateurs :');
  const users = db.prepare('SELECT id, username, role, created_at FROM users ORDER BY id').all();
  users.forEach(u => {
    const date = u.created_at ? new Date(u.created_at).toLocaleDateString('fr-FR') : '—';
    console.log(`   #${u.id} ${u.username.padEnd(20)} ${u.role.padEnd(8)} créé le ${date}`);
  });
  db.close();
  process.exit(0);
}

// Mode reset : supprimer la base
if (isReset) {
  if (fs.existsSync(DB_PATH)) {
    console.log('⚠️  Suppression de la base existante…');
    fs.unlinkSync(DB_PATH);
    // Supprimer aussi les fichiers WAL
    if (fs.existsSync(DB_PATH + '-wal')) fs.unlinkSync(DB_PATH + '-wal');
    if (fs.existsSync(DB_PATH + '-shm')) fs.unlinkSync(DB_PATH + '-shm');
  }
}

// Vérifier que le schéma existe
if (!fs.existsSync(SCHEMA_PATH)) {
  console.error('❌ Fichier schema.sql introuvable :', SCHEMA_PATH);
  process.exit(1);
}

// Créer / mettre à jour la base
const existed = fs.existsSync(DB_PATH);
const db = new sqlite3(DB_PATH);
const schema = fs.readFileSync(SCHEMA_PATH, 'utf8');

try {
  db.exec(schema);
  console.log(existed ? '✅ Base mise à jour' : '✅ Base créée');
  console.log('');

  // Vérifier les tables
  const tables = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").all();
  console.log('📋 Tables :');
  tables.forEach(t => console.log('   -', t.name));

  // Compter les utilisateurs
  const userCount = db.prepare('SELECT COUNT(*) AS c FROM users').get().c;
  const adminCount = db.prepare("SELECT COUNT(*) AS c FROM users WHERE role = 'admin'").get().c;

  console.log('');
  console.log(`👥 Utilisateurs : ${userCount} (dont ${adminCount} admin${adminCount > 1 ? 's' : ''})`);

  if (adminCount === 0) {
    console.log('');
    console.log('ℹ️  Aucun administrateur.');
    console.log('   → Démarrez le serveur et ouvrez http://localhost:3000');
    console.log('   → L\'assistant d\'installation vous guidera.');
  }

  db.close();
  console.log('');
  console.log('✨ Terminé.');
} catch (e) {
  console.error('❌ Erreur :', e.message);
  db.close();
  process.exit(1);
}