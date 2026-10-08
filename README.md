# Ma Plateforme E-learning

Une plateforme de cours en ligne auto-hébergée, légère et open source.
Lecteur vidéo intégré, suivi de progression, sous-titres VTT, gestion multi-utilisateurs.

## ✨ Fonctionnalités

- 🎬 **Lecteur vidéo** avec support HTTP Range (seek, reprise)
- 📚 **Organisation par cours** : dossiers, leçons, tri intelligent
- 💬 **Sous-titres VTT** détectés automatiquement (`video.fr.vtt`, `video.en.vtt`, dossier `subtitles/`)
- ⏪ **Reprise automatique** : la position est sauvegardée toutes les 10 secondes
- 👥 **Multi-utilisateurs** : admin + utilisateurs (lecture seule)
- 📊 **Suivi de progression** : % par cours, cours "en cours", cours "archivés"
- 🔐 **Authentification** par JWT
- 💾 **Aucune copie des vidéos** : lecture directe depuis un dossier monté (rclone, disque local, NFS…)
- 🎨 **Interface type Udemy** : sidebar des leçons + lecteur principal
- ⚙️ **Assistant d'installation** : au premier lancement, une page web vous guide

## 📋 Prérequis

- Node.js 18+
- Un dossier contenant vos cours vidéo (accessible en lecture)
- Ubuntu 22.04 ou équivalent Debian

## 🚀 Installation rapide

```bash
git clone https://github.com/VOTRE_USERNAME/elearning.git
cd elearning
npm install
MEDIA_ROOT=/chemin/vers/vos/cours node server.js

PORT	3000	Port d'écoute
MEDIA_ROOT	/mnt/yandex_disk	Dossier racine des cours
JWT_SECRET	Auto-généré	Secret pour les tokens (généré dans .config.json)