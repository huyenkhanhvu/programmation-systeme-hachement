# HACHEMENT — Table de hachage persistante en C

Projet universitaire de programmation système : conception et implémentation d'une table de hachage stockée dans un fichier, permettant de gérer des chaînes de caractères et des fichiers, avec prise en compte des accès concurrents.

## Présentation

HACHEMENT est un programme en ligne de commande écrit en C. Les données sont conservées dans un fichier binaire de table de hachage et restent disponibles entre deux exécutions.

Le projet met en pratique la programmation système sous environnement POSIX : gestion des fichiers, mappage mémoire `mmap`, verrous `fcntl`, synchronisation avec des mutex POSIX `pthread` et manipulation de structures de données.

## Fonctionnalités

- Création d'une table de hachage persistante.
- Insertion de chaînes de caractères et de fichiers.
- Insertion de lignes provenant d'un fichier texte.
- Recherche d'une chaîne ou d'un nom de fichier.
- Suppression d'une chaîne ou des objets associés à un hashcode.
- Consultation de l'occupation de la table.
- Vérification de la cohérence de la table et détection de certaines corruptions.
- Agrandissement, réduction et ajustement de la taille de la table.
- Synchronisation des accès aux blocs avec des verrous de fichiers et des mutex.

## Fonctionnement technique

### Organisation des données

La table repose sur des blocs de 1024 octets. Chaque entrée contient notamment des informations de chaînage, la longueur et le type de l'objet, ainsi qu'une zone de données de 1008 octets. Les objets volumineux peuvent s'étendre sur plusieurs blocs. Les collisions sont gérées au moyen de chaînes de blocs.

### Fonctions de hachage

La fonction de hachage dépend de l'extension de la table :

- `.cks` : somme de contrôle sur 32 bits (checksum32).
- `.sha` : calcul basé sur SHA-1 via OpenSSL.

SHA-1 est utilisé ici comme fonction de hachage dans le cadre d'un projet pédagogique, pas comme mécanisme de sécurité cryptographique moderne.

### Accès concurrents

Le programme utilise des verrous POSIX (`fcntl`) sur les blocs et des mutex (`pthread`) pour coordonner certaines opérations. Un paramètre `slowns` permet d'introduire un délai en nanosecondes lors du déverrouillage, notamment pour étudier le comportement concurrent.

## Prérequis

- Un environnement compatible POSIX (Linux recommandé).
- Un compilateur C, par exemple `gcc`.
- `make`.
- La bibliothèque de développement OpenSSL/libcrypto.
- Le support de pthread.

Sur une distribution Debian/Ubuntu, les outils nécessaires peuvent être installés avec :

```
sudo apt update
sudo apt install build-essential libssl-dev
```

## Installation et compilation

```
git clone https://github.com/huyenkhanhvu/programmation-systeme-hachement.git
cd programmation-systeme-hachement
make
```

La compilation produit un exécutable nommé `hachement`. Le `Makefile` utilise `gcc` avec `-Wall -Wextra -O2`, et lie le programme avec `-lcrypto -pthread`.

Pour supprimer l'exécutable et les fichiers de table générés dans le dossier courant :

```
make clean
```

**Attention :** `make clean` supprime également les fichiers `*.cks` et `*.sha` du répertoire courant. Sauvegardez vos tables avant de l'exécuter.

## Utilisation

Syntaxe générale :

```
./hachement <commande> <table> <slowns> [arguments]
```

- `<table>` : nom du fichier de table, avec extension `.cks` ou `.sha`.
- `<slowns>` : délai en nanosecondes (mettre `0` pour ne pas ajouter de délai).
- `[arguments]` : paramètres propres à chaque commande.

### Exemple de prise en main

Créer une table de 128 blocs :

```
./hachement make exemple.cks 0 128
```

Insérer deux chaînes :

```
./hachement insertstring exemple.cks 0 "bonjour"
./hachement insertstring exemple.cks 0 "programmation systeme"
```

Rechercher une chaîne :

```
./hachement lookup exemple.cks 0 "bonjour"
```

Afficher les informations d'occupation et vérifier la table :

```
./hachement free exemple.cks 0
./hachement check exemple.cks 0
```

Supprimer une chaîne :

```
./hachement delete exemple.cks 0 "bonjour"
```

### Commandes disponibles

| Commande | Description | Argument supplémentaire |
| --- | --- | --- |
| `make` | Créer une table vide | Nombre de blocs |
| `free` | Afficher l'occupation de la table | Aucun |
| `insertstring` | Insérer une chaîne | Chaîne |
| `insertfile` | Insérer un fichier | Chemin du fichier |
| `insertlines` | Insérer des lignes d'un fichier texte | Chemin du fichier |
| `lookup` | Rechercher une chaîne ou un nom de fichier | Chaîne ou nom |
| `delete` | Supprimer une chaîne exacte | Chaîne |
| `deletehash` | Supprimer les objets d'un hashcode | Hashcode (décimal ou hexadécimal) |
| `check` | Vérifier la cohérence de la table | Aucun |
| `extend` | Doubler le nombre de blocs | Aucun |
| `shrink` | Réduire le nombre de blocs de moitié | Aucun |
| `ajust` | Ajuster la taille selon le taux d'occupation | Aucun |

Exemple pour insérer un fichier :

```
./hachement insertfile exemple.cks 0 document.txt
```

Exemple de redimensionnement :

```
./hachement extend exemple.cks 0
./hachement ajust exemple.cks 0
```

La commande `ajust` agrandit la table au-dessus de 70 % d'occupation et cherche à la réduire sous 10 %, si les contraintes de taille le permettent.

## Structure du dépôt

```text
programmation-systeme-hachement/
├── hachement.c         # Implémentation et interface en ligne de commande
├── Makefile            # Règles de compilation et de nettoyage
├── rapport-progsys.pdf # Rapport du projet
└── README.md           # Documentation du projet
```

## Compétences mobilisées

C, Programmation système, Linux/POSIX, Structures de données, Tables de hachage, Gestion mémoire, Fichiers binaires, mmap, fcntl, pthread, Synchronisation, Makefile, OpenSSL

## Documentation

Le [rapport du projet](rapport-progsys.pdf) fournit des informations complémentaires sur sa conception et sa réalisation.