#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <libgen.h>
#include <openssl/sha.h>
#include <pthread.h>

#define BLOC_SIZE 1024
#define BLOC_CONS 0xffffffffUL
#define OBJ_SIZE  1008

#define TYPE_LIBRE   0
#define TYPE_STRING  1
#define TYPE_FILE    2

#define NHASH_MUTEX 1024

struct hache_entree {
    uint32_t premier;
    uint32_t suivant;
    uint32_t longueur;
    uint32_t type;
    char     obj[OBJ_SIZE];
};

struct meta_fichier {
    uint64_t taille;
    int64_t  mtime;
    uint32_t mode;
    uint32_t nom_len;
};

struct zone_arg {
    const char *src;
    size_t taille;
    size_t debut;
    size_t fin;
    struct hache_entree *t;
    uint32_t b;
    int fd;
    const char *fname;
};

uint64_t G_slowns = 0;

pthread_mutex_t G_hash_mutex[NHASH_MUTEX];
pthread_mutex_t G_alloc_mutex = PTHREAD_MUTEX_INITIALIZER;
uint32_t G_alloc_hint = 0;

/* Initialisation des mutex */
void init_mutexes(void) {
    for (int i = 0; i < NHASH_MUTEX; i++)
        pthread_mutex_init(&G_hash_mutex[i], NULL);
}

/* Attend le temps demander */
void wait_slowns(void) {
    if (!G_slowns) 
        return;
    
    struct timespec ts = { 
        (time_t)(G_slowns / 1000000000UL),
        (long)(G_slowns % 1000000000UL) 
    };

    nanosleep(&ts, NULL);
}

/* Verrouillage pour concu */
void verr_bloc(int fd, uint32_t i, int type) {
    struct flock fl;
    memset(&fl, 0, sizeof fl);
    fl.l_type = type;
    fl.l_whence = SEEK_SET;
    fl.l_start = (off_t)i * BLOC_SIZE;
    fl.l_len = BLOC_SIZE;
    if (fcntl(fd, F_SETLKW, &fl) == -1) {
        perror("fcntl lock bloc");
        exit(EXIT_FAILURE);
    }
}

/* Déverouille pour concu */
void deverr_bloc(int fd, uint32_t i) {
    wait_slowns();
    struct flock fl;
    memset(&fl, 0, sizeof fl);
    fl.l_type = F_UNLCK;
    fl.l_whence = SEEK_SET;
    fl.l_start = (off_t)i * BLOC_SIZE;
    fl.l_len = BLOC_SIZE;
    fcntl(fd, F_SETLK, &fl);
}

/* Verrou global pour make */
void verr_table(int fd, int type) {
    struct flock fl;
    memset(&fl, 0, sizeof fl);
    fl.l_type = type;
    fl.l_whence = SEEK_SET;
    fl.l_start = 0;
    fl.l_len = 0;
    if (fcntl(fd, F_SETLKW, &fl) == -1) {
        perror("fcntl lock table");
        exit(EXIT_FAILURE);
    }
}

/* Unlock globale pour make */
void deverr_table(int fd) {
    struct flock fl;
    memset(&fl, 0, sizeof fl);
    fl.l_type = F_UNLCK;
    fl.l_whence = SEEK_SET;
    fl.l_start = 0;
    fl.l_len = 0;
    fcntl(fd, F_SETLK, &fl);
}

/* Fonction de hashage cks32 + sha (avec la fonction de choix) (les shift bizarre c'est pour le choix du boutisme (en esperant qu'on se trompe pas bahaha))*/
uint32_t checksum32(const uint8_t *C, size_t n, uint32_t b) {
    uint32_t s = 0;
    size_t i = 0;
    while (i < n) {
        uint8_t b0 = (i < n) ? C[i++] : 0;
        uint8_t b1 = (i < n) ? C[i++] : 0;
        uint8_t b2 = (i < n) ? C[i++] : 0;
        uint8_t b3 = (i < n) ? C[i++] : 0;
        s += ((uint32_t)b0 << 24) | ((uint32_t)b1 << 16) | ((uint32_t)b2 <<  8) |  (uint32_t)b3;
    }
    return s % b;
}

uint32_t sha1_hash(const uint8_t *C, size_t n, uint32_t b) {
    unsigned char h[SHA_DIGEST_LENGTH];
    SHA1(C, n, h);
    uint32_t v = ((uint32_t)h[16] << 24) | ((uint32_t)h[17] << 16) | ((uint32_t)h[18] <<  8) |  (uint32_t)h[19];
    return v % b;
}

uint32_t calculer_hash(const char *fname, const uint8_t *C, size_t n, uint32_t b) {
    size_t l = strlen(fname);
    if (l >= 4 && !strcmp(fname + l - 4, ".cks")) 
        return checksum32(C, n, b);
    if (l >= 4 && !strcmp(fname + l - 4, ".sha")) 
        return sha1_hash(C, n, b);
    
    fprintf(stderr, "Erreur : extension .cks ou .sha attendue\n");
    exit(EXIT_FAILURE);
}

/* fonctions d'ouverture/fermeture des tables pour la suite*/
struct hache_entree *ouvrir_table(const char *fname, uint32_t *b_out, int *fd_out, size_t *sz_out) {
    int fd = open(fname, O_RDWR);
    if (fd == -1) {
        fprintf(stderr, "Erreur : ouverture de '%s' impossible (%s)\n",fname, strerror(errno));
        exit(EXIT_FAILURE);
    }

    struct stat st;
    if (fstat(fd, &st) == -1) { 
        perror("fstat"); 
        close(fd); 
        exit(EXIT_FAILURE); 
    }

    if (st.st_size <= 0 || (size_t)st.st_size % BLOC_SIZE != 0) {
        fprintf(stderr, "Erreur : taille de '%s' invalide (%ld octets)\n", fname, (long)st.st_size);
        close(fd); 
        exit(EXIT_FAILURE);
    }

    void *m = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (m == MAP_FAILED) { 
        perror("mmap"); 
        close(fd); 
        exit(EXIT_FAILURE); 
    }

    *b_out  = (uint32_t)(st.st_size / BLOC_SIZE);
    *fd_out = fd;
    *sz_out = (size_t)st.st_size;
    return (struct hache_entree *)m;
}

void fermer_table(struct hache_entree *t, int fd, size_t sz) {
    if (msync(t, sz, MS_SYNC) == -1) 
        perror("msync");
    munmap(t, sz);
    close(fd);
}

/* Cherche un bloc libre, le verrouille en ecriture. return BLOC_CONS si plein, si trouver le bloc reste verr. */
uint32_t reserver_bloc_libre(struct hache_entree *t, uint32_t b, int fd, uint32_t skip) {
    pthread_mutex_lock(&G_alloc_mutex);
    uint32_t depart = G_alloc_hint % b;
    for (uint32_t n = 0; n < b; n++) {
        uint32_t i = depart + n;
        if (i >= b) i -= b;
        if (i == skip) continue;
        verr_bloc(fd, i, F_WRLCK);
        if (t[i].longueur == BLOC_CONS) {
            t[i].longueur = 0; /* reservé, plus libre */
            G_alloc_hint = (i + 1 == b) ? 0 : i + 1;
            pthread_mutex_unlock(&G_alloc_mutex);
            return i;
        }
        deverr_bloc(fd, i);
    }
    pthread_mutex_unlock(&G_alloc_mutex);
    return BLOC_CONS;
}

/* Lit un objet en chainant les blocs (en verrouillant chacun) le 1er bloc est verr en lecture par l'appel (et reste verr après), les blocs suivants sont verr/libérés ici. */
char *lire_objet(struct hache_entree *t, int fd, uint32_t start, size_t *taille_out, uint32_t *type_out) {
    size_t total = t[start].longueur;
    if (type_out) *type_out = t[start].type;
    char *buf = malloc(total + 1);
    if (!buf) { 
        perror("malloc"); 
        exit(EXIT_FAILURE); 
    }

    size_t copies = 0;
    size_t reste = total;
    size_t a = reste > OBJ_SIZE ? OBJ_SIZE : reste;
    memcpy(buf, t[start].obj, a);
    copies += a;
    reste -= a;

    uint32_t curr = start;
    while (reste > 0) {
        uint32_t next = t[curr].suivant;
        if (next == BLOC_CONS) {
            fprintf(stderr, "Erreur : chaine cassee au bloc %u\n", curr);
            free(buf);
            return NULL;
        }
        verr_bloc(fd, next, F_RDLCK);
        a = reste > OBJ_SIZE ? OBJ_SIZE : reste;
        memcpy(buf + copies, t[next].obj, a);
        copies += a;
        reste -= a;
        deverr_bloc(fd, next);
        curr = next;
    }
    buf[total] = 0;
    *taille_out = total;
    return buf;
}

/* Ecrit un objet sur un ou plusieurs blocs */
int ecrire_objet(struct hache_entree *t, uint32_t b, int fd, uint32_t start, uint32_t type, const char *donnees, size_t total_len, uint32_t skip) {
    uint32_t curr = start;
    size_t reste = total_len;
    size_t off = 0;
    int first = 1;
    while (reste > 0 || first) {
        size_t a = reste > OBJ_SIZE ? OBJ_SIZE : reste;
        memcpy(t[curr].obj, donnees + off, a);

        t[curr].longueur = reste;
        t[curr].type = type;
        off += a;
        reste -= a;
        if (reste == 0) {
            t[curr].suivant = BLOC_CONS;
            deverr_bloc(fd, curr);
            return 0;
        }

        uint32_t next = reserver_bloc_libre(t, b, fd, skip);
        if (next == BLOC_CONS) {
            t[curr].suivant = BLOC_CONS;
            deverr_bloc(fd, curr);
            fprintf(stderr, "Erreur : table pleine pendant l'ecriture\n");
            return -1;
        }

        /* le bloc next a été marqué premier=next à l'init, on indique qu'il n'est plus une tête*/
        if (t[next].premier == next) t[next].premier = BLOC_CONS;
        t[curr].suivant = next;
        deverr_bloc(fd, curr);
        curr = next;
        first = 0;
    }
    return 0;
}

/* Commande qui crée une table vide */
void commande_make(const char *fname, uint32_t b) {
    if (b == 0) {
        fprintf(stderr, "Erreur : nombre de bloc doit être > 0\n");
        exit(EXIT_FAILURE);
    }

    int fd = open(fname, O_RDWR | O_CREAT | O_TRUNC, 0666);
    if (fd == -1) { 
        perror("open"); 
        exit(EXIT_FAILURE); 
    }
    verr_table(fd, F_WRLCK);
    size_t sz = (size_t)b * BLOC_SIZE;
    if (ftruncate(fd, sz) == -1) {
        perror("ftruncate");
        deverr_table(fd); 
        close(fd); 
        exit(EXIT_FAILURE);
    }

    struct hache_entree *t = mmap(NULL, sz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (t == MAP_FAILED) {
        perror("mmap");
        deverr_table(fd); 
        close(fd); 
        exit(EXIT_FAILURE);
    }

    for (uint32_t i = 0; i < b; i++) {
        t[i].premier = i;
        t[i].suivant = BLOC_CONS;
        t[i].longueur = BLOC_CONS;
        t[i].type = TYPE_LIBRE;
    }
    msync(t, sz, MS_SYNC);
    munmap(t, sz);
    deverr_table(fd);
    close(fd);
}

/* Commande qui affiches ce qui reste de "free" avec le taux de remplissage, etc...*/
void commande_free(const char *fname) {
    uint32_t b; int fd; size_t sz;
    struct hache_entree *t = ouvrir_table(fname, &b, &fd, &sz);

    uint32_t libres = 0, occupes = 0, n_obj = 0, n_str = 0, n_file = 0;

    /* vérification des blocs libres*/
    for (uint32_t i = 0; i < b; i++) {
        verr_bloc(fd, i, F_RDLCK);
        if (t[i].longueur == BLOC_CONS) { // Vérif que le bloc est bien libre
            libres++;
        } else {
            occupes++; /* Ici on compte de façon naive, la différenciation pour les multi-bloc seront fait sur la seconde boucle (peux être possible en 1seulme boucle mais solution naive la plus claire)*/
        }
        deverr_bloc(fd, i);
    }

    /* comptage du nombre d'objets en suivant les chaines */
    for (uint32_t h = 0; h < b; h++) {
        verr_bloc(fd, h, F_RDLCK);
        uint32_t p = t[h].premier;
        deverr_bloc(fd, h);
        if (p == BLOC_CONS) 
            continue;

        uint32_t cur = p;
        while (cur != BLOC_CONS) {
            verr_bloc(fd, cur, F_RDLCK);
            if (t[cur].longueur == BLOC_CONS) { 
                deverr_bloc(fd, cur); 
                break; 
            }

            n_obj++;
            if (t[cur].type == TYPE_STRING) 
                n_str++;
            else if (t[cur].type == TYPE_FILE) 
                n_file++;

            /* sauter les blocs internes de l'objet courant */
            size_t reste = t[cur].longueur;
            uint32_t suiv = t[cur].suivant;
            deverr_bloc(fd, cur);
            while (reste > OBJ_SIZE && suiv != BLOC_CONS) {
                reste -= OBJ_SIZE;
                verr_bloc(fd, suiv, F_RDLCK);
                uint32_t s = t[suiv].suivant;
                deverr_bloc(fd, suiv);
                cur = suiv;
                suiv = s;
            }
            cur = suiv;
        }
    }

    double taux = ((double)occupes / b) * 100.0;
    printf("Table '%s' (%u blocs au total) :\n", fname, b);
    printf("- Blocs libres : %u\n", libres);
    printf("- Blocs occupés : %u\n", occupes);
    printf("- Taux de remplissage : %.2f%%\n", taux);
    printf("- Objets totaux : %u (%u chaines, %u fichiers)\n", n_obj, n_str, n_file);
    fermer_table(t, fd, sz);
}

/* Compare un objet stocké à partir du bloc start avec donnees/len start doit être verrouillé en lecture par l'appelant. */
int comparer_objet(struct hache_entree *t, int fd, uint32_t start, const char *donnees, size_t len) {
    if (t[start].longueur != len) 
        return 0;

    size_t copies = 0, reste = len;
    size_t a = reste > OBJ_SIZE ? OBJ_SIZE : reste; /* Compare le premier bloc */
    if (memcmp(t[start].obj, donnees, a) != 0) 
        return 0;

    copies += a; 
    reste -= a;
    uint32_t curr = start;
    while (reste > 0) {  /* Continue la comparaison si l'objet a plsuieur blocc */
        uint32_t next = t[curr].suivant;
        
        if (next == BLOC_CONS) /* Chaîne incomplète/corrompue */
            return 0;
        
        verr_bloc(fd, next, F_RDLCK);
        a = reste > OBJ_SIZE ? OBJ_SIZE : reste;
       
        int eq = memcmp(t[next].obj, donnees + copies, a) == 0;/* Compare le morceau suivant des données */
        deverr_bloc(fd, next);
        if (!eq) 
            return 0;
        copies += a; 
        reste -= a;
        curr = next;
    }
    return 1;
}

/* Insertion d'une chaine dans une table déjà avec impl des thread */
int inserer_chaine(struct hache_entree *t, uint32_t b, int fd, const char *fname, uint32_t type, const char *chaine, size_t len) {
    uint32_t h = calculer_hash(fname, (const uint8_t *)chaine, len, b);

    verr_bloc(fd, h, F_WRLCK);
    uint32_t tete = t[h].premier;

    /* Si la case initiale et libre, on insert direct */
    if (tete == h && t[h].longueur == BLOC_CONS) {
        t[h].longueur = 0;
        if (ecrire_objet(t, b, fd, h, type, chaine, len, BLOC_CONS) == -1)
            return -1;
        return 0;
    }

    /* pas de chaîne pour h (premier(h)==BLOC_CONS) */
    if (tete == BLOC_CONS) {
        uint32_t nv = reserver_bloc_libre(t, b, fd, h);
        if (nv == BLOC_CONS) {
            deverr_bloc(fd, h);
            return -1;
        }
        /* Le bloc vas ce chainer */
        if (t[nv].premier == nv) 
            t[nv].premier = BLOC_CONS;
        if (ecrire_objet(t, b, fd, nv, type, chaine, len, h) == -1) {
            deverr_bloc(fd, h);
            return -1;
        }

        /* La chaîne associée au hash commence maintenant à nv */
        t[h].premier = nv;
        deverr_bloc(fd, h);
        return 0;
    }

    /* Une chaîne existe déjà : parcours + détection doublon */
    uint32_t cur = tete;
    int doublon = 0;

    /* descend la chaine objet par objet */
    if (cur != h)
        verr_bloc(fd, cur, F_RDLCK);

    uint32_t dernier = BLOC_CONS;
    while (1) {

        /* Vérifier si l'objet existe */
        if (t[cur].type == type && comparer_objet(t, fd, cur, chaine, len)) {
            doublon = 1;
        }

        /* sauter à la fin de l'objet */
        size_t reste = t[cur].longueur;
        uint32_t suiv = t[cur].suivant;
        uint32_t fin_obj = cur;
        if (cur != h) 
            deverr_bloc(fd, cur);

        while (reste > OBJ_SIZE && suiv != BLOC_CONS) {
            reste -= OBJ_SIZE;
            if (suiv != h) 
                verr_bloc(fd, suiv, F_RDLCK);
            fin_obj = suiv;
            uint32_t s = t[suiv].suivant;
            if (suiv != h) 
                deverr_bloc(fd, suiv);
            suiv = s;
        }
        /* fin_obj = dernier bloc de l'objet cournat donc le suiv = bloc suivant ou BLOC_CONS */
        dernier = fin_obj;
        if (suiv == BLOC_CONS) 
            break;

        if (suiv != h) 
            verr_bloc(fd, suiv, F_RDLCK);

        cur = suiv;
    }

    if (doublon) {
        deverr_bloc(fd, h);
        return 1;
    }

    /* Ajout du nouvel objet a la fin de la chaine */
    uint32_t nv = reserver_bloc_libre(t, b, fd, h);
    if (nv == BLOC_CONS) {
        deverr_bloc(fd, h);
        return -1;
    }
    if (t[nv].premier == nv) 
        t[nv].premier = BLOC_CONS;
    if (dernier != h) 
        verr_bloc(fd, dernier, F_WRLCK);
    t[dernier].suivant = nv;
    if (dernier != h) 
        deverr_bloc(fd, dernier);
    if (ecrire_objet(t, b, fd, nv, type, chaine, len, h) == -1) {
        deverr_bloc(fd, h);
        return -1;
    }
    deverr_bloc(fd, h);
    return 0;
}

/* Insertion d'une string*/
void commande_insertstring(const char *fname, const char *chaine) {
    uint32_t b; int fd; size_t sz;
    struct hache_entree *t = ouvrir_table(fname, &b, &fd, &sz);

    int r = inserer_chaine(t, b, fd, fname, TYPE_STRING, chaine, strlen(chaine));
    if (r == 1)
        fprintf(stderr, "Warning : chaine deja presente, table inchangee\n");

    fermer_table(t, fd, sz);
    if (r == -1) {
        fprintf(stderr, "Erreur : table pleine\n");
        exit(EXIT_FAILURE);
    }
}

/* Vérifie sir le bloc actuelle correspod a un objet fichier dont le nom est demander */
int fichier_nom_correspond(struct hache_entree *t, uint32_t cur, const char *cible, size_t cible_len) {
    if (t[cur].type != TYPE_FILE) 
        return 0;

    if (t[cur].longueur < sizeof(struct meta_fichier)) 
        return 0;

    struct meta_fichier mf;
    memcpy(&mf, t[cur].obj, sizeof mf);
    if (mf.nom_len != cible_len) 
        return 0;

    if (sizeof(struct meta_fichier) + mf.nom_len > OBJ_SIZE) 
        return 0;

    return memcmp(t[cur].obj + sizeof(struct meta_fichier), cible, cible_len) == 0;
}

/* Commande de recherche + intéraction selon demande */
void commande_lookup(const char *fname, const char *chaine) {
    uint32_t b; int fd; size_t sz;
    
    struct hache_entree *t = ouvrir_table(fname, &b, &fd, &sz);
    size_t len = strlen(chaine);
    uint32_t h = calculer_hash(fname, (const uint8_t *)chaine, len, b);

    int trouve = 0;
    uint32_t nb_fic = 0;

    /* Parcourir la chaîne des hashcodes pour les chaînes */
    verr_bloc(fd, h, F_RDLCK);
    uint32_t cur = t[h].premier;
    deverr_bloc(fd, h);

    while (cur != BLOC_CONS) {
        verr_bloc(fd, cur, F_RDLCK);
        if (t[cur].longueur == BLOC_CONS) { 
            deverr_bloc(fd, cur); 
            break; 
        }

        if (t[cur].type == TYPE_STRING && comparer_objet(t, fd, cur, chaine, len)) {
            trouve = 1;
        }

        /* Parcours multi-blocs pour un objet long */
        size_t reste = t[cur].longueur;
        uint32_t suiv = t[cur].suivant;
        deverr_bloc(fd, cur);
        while (reste > OBJ_SIZE && suiv != BLOC_CONS) {
            reste -= OBJ_SIZE;
            verr_bloc(fd, suiv, F_RDLCK);
            uint32_t s = t[suiv].suivant;
            deverr_bloc(fd, suiv);
            suiv = s;
        }
        cur = suiv;
    }

    /* Parcourir la table pour les fichiers portant ce nom */
    for (uint32_t hh = 0; hh < b; hh++) {
        verr_bloc(fd, hh, F_RDLCK);
        uint32_t c = t[hh].premier;
        deverr_bloc(fd, hh);
        if (c == BLOC_CONS) 
            continue;

        while (c != BLOC_CONS) {
            verr_bloc(fd, c, F_RDLCK);
            if (t[c].longueur == BLOC_CONS) { 
                deverr_bloc(fd, c); 
                break; 
            }

            if (fichier_nom_correspond(t, c, chaine, len)) 
                nb_fic++;

            size_t reste = t[c].longueur;
            uint32_t suiv = t[c].suivant;
            deverr_bloc(fd, c);
            while (reste > OBJ_SIZE && suiv != BLOC_CONS) {
                reste -= OBJ_SIZE;
                verr_bloc(fd, suiv, F_RDLCK);
                uint32_t s = t[suiv].suivant;
                deverr_bloc(fd, suiv);
                suiv = s;
            }
            c = suiv;
        }
    }

    /* Affichage final : seulement après avoir parcouru tout */
    if (trouve)
        printf("Chaîne trouvée : '%s' (hashcode %u)\n", chaine, h);
    if (nb_fic > 0)
        printf("Fichier(s) nommé(s) '%s' : %u trouvé(s)\n", chaine, nb_fic);

    if (!trouve && nb_fic == 0)
        printf("Chaîne ou fichier non trouvé : '%s' (hashcode %u)\n", chaine, h);

    fermer_table(t, fd, sz);
}
/* Supprime tous les obj associer au haschode donner */
void commande_deletehash(const char *fname, uint32_t hash_cible) {
    uint32_t b; int fd; size_t sz;
    struct hache_entree *t = ouvrir_table(fname, &b, &fd, &sz);
    if (hash_cible >= b) {
        fprintf(stderr, "Erreur : hashcode %u hors limites (b=%u)\n", hash_cible, b);
        fermer_table(t, fd, sz); 
        exit(EXIT_FAILURE);
    }

    verr_bloc(fd, hash_cible, F_WRLCK);
    uint32_t cur = t[hash_cible].premier;
    if (cur == BLOC_CONS || (cur == hash_cible && t[hash_cible].longueur == BLOC_CONS)) {
        deverr_bloc(fd, hash_cible);
        fprintf(stderr, "Warning : aucune entree au hashcode %u\n", hash_cible);
        fermer_table(t, fd, sz);
        return;
    }

    /* libérer tous les blocs de la chaine */
    uint32_t suppr = 0;
    uint32_t bloc = cur;
    while (bloc != BLOC_CONS) {
        if (bloc != hash_cible) 
            verr_bloc(fd, bloc, F_WRLCK);

        uint32_t next = t[bloc].suivant;
        t[bloc].longueur = BLOC_CONS;
        t[bloc].suivant = BLOC_CONS;
        t[bloc].type = TYPE_LIBRE;

        if (t[bloc].premier == BLOC_CONS) 
            t[bloc].premier = bloc;
        suppr++;
        
        if (bloc != hash_cible) 
            deverr_bloc(fd, bloc);
        bloc = next;
    }

    t[hash_cible].premier = hash_cible;
    deverr_bloc(fd, hash_cible);
    printf("Supprimé : %u bloc(s) au hashcode %u\n", suppr, hash_cible);
    fermer_table(t, fd, sz);
}

/* Supprime les chaines correspondant exactement a la valeur donner */
void commande_delete(const char *fname, const char *chaine) {
    uint32_t b; int fd; size_t sz;
    struct hache_entree *t = ouvrir_table(fname, &b, &fd, &sz);
    size_t len = strlen(chaine);
    uint32_t h = calculer_hash(fname, (const uint8_t *)chaine, len, b);

    verr_bloc(fd, h, F_WRLCK);
    uint32_t cur = t[h].premier;
    if (cur == BLOC_CONS) {
        deverr_bloc(fd, h);
        fprintf(stderr, "Warning : '%s' introuvable\n", chaine);
        fermer_table(t, fd, sz); return;
    }

    uint32_t prec_fin = BLOC_CONS; // dernier bloc de l'objet précédent dans la chaine pour la reconnection
    int trouve = 0;
    uint32_t debut_obj = cur, fin_obj = cur;
    uint32_t suite = BLOC_CONS; // Le bloc a reconnecter après
    while (cur != BLOC_CONS && !trouve) {
        if (cur != h) 
            verr_bloc(fd, cur, F_RDLCK);

        if (t[cur].longueur == BLOC_CONS) { 
            if (cur != h) 
                deverr_bloc(fd, cur); 
            
            break; 
        }

        int match = (t[cur].type == TYPE_STRING && comparer_objet(t, fd, cur, chaine, len));
        size_t reste = t[cur].longueur;
        uint32_t suiv = t[cur].suivant;
        uint32_t fin = cur;
        if (cur != h) 
            deverr_bloc(fd, cur);

        while (reste > OBJ_SIZE && suiv != BLOC_CONS) {
            reste -= OBJ_SIZE;
            verr_bloc(fd, suiv, F_RDLCK);
            fin = suiv;
            uint32_t s = t[suiv].suivant;
            deverr_bloc(fd, suiv);
            suiv = s;
        }

        if (match) {
            trouve = 1;
            debut_obj = cur;
            fin_obj = fin;
            suite = suiv; /* objet suivant dans la chaîne de collision */
            break;
        }

        prec_fin = fin;
        cur = suiv;
    }

    if (!trouve) {
        deverr_bloc(fd, h);
        fprintf(stderr, "Warning : '%s' introuvable\n", chaine);
        fermer_table(t, fd, sz); 
        return;
    }

    /* libérer tous les blocs de debut_obj a fin_obj */
    uint32_t bb = debut_obj;
    while (bb != BLOC_CONS) {
        if (bb != h) 
            verr_bloc(fd, bb, F_WRLCK);

        uint32_t nx = t[bb].suivant;
        t[bb].longueur = BLOC_CONS;
        t[bb].suivant = BLOC_CONS;
        t[bb].type = TYPE_LIBRE;
        if (t[bb].premier == BLOC_CONS) 
            t[bb].premier = bb;

        if (bb != h) 
            deverr_bloc(fd, bb);

        if (bb == fin_obj) 
            break;

        bb = nx;
    }
    /* rattacher la chaîne */
    if (prec_fin == BLOC_CONS) {
        t[h].premier = (suite == BLOC_CONS) ? BLOC_CONS : suite;
        if (suite == BLOC_CONS && debut_obj == h) {
            t[h].premier = h;
        }
    } else {
        verr_bloc(fd, prec_fin, F_WRLCK);
        t[prec_fin].suivant = suite;
        deverr_bloc(fd, prec_fin);
    }
    
    deverr_bloc(fd, h);
    printf("Supprimé : '%s' (hashcode %u)\n", chaine, h);
    fermer_table(t, fd, sz);
}

/* Relécture d'un objet bloc par bloc */
char *lire_objet_check(struct hache_entree *t, int fd, uint32_t b, uint32_t start, size_t *taille_out, uint32_t *type_out, uint32_t *suivant_out) {
    if (start >= b) {
        fprintf(stderr, "Corruption : bloc de depart invalide %u\n", start);
        return NULL;
    }

    size_t total = t[start].longueur;
    if (total == BLOC_CONS) {
        fprintf(stderr, "Corruption : bloc libre utilise comme objet %u\n", start);
        return NULL;
    }
    if (total > (size_t)b * OBJ_SIZE) {
        fprintf(stderr, "Corruption : longueur impossible %zu au bloc %u\n", total, start);
        return NULL;
    }

    if (type_out) *type_out = t[start].type;
    char *buf = malloc(total + 1);
    if (!buf) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }

    size_t copies = 0;
    size_t reste = total;
    size_t a = reste > OBJ_SIZE ? OBJ_SIZE : reste;
    memcpy(buf, t[start].obj, a);
    copies += a;
    reste -= a;

    uint32_t next = t[start].suivant;
    uint32_t precedent = start;
    while (reste > 0) {
        if (next == BLOC_CONS) {
            fprintf(stderr, "Erreur : chaine cassee au bloc %u\n", precedent);
            free(buf);
            return NULL;
        }
        if (next >= b) {
            fprintf(stderr, "Corruption : bloc suivant invalide %u depuis %u\n", next, precedent);
            free(buf);
            return NULL;
        }

        verr_bloc(fd, next, F_RDLCK);
        if (t[next].longueur == BLOC_CONS) {
            deverr_bloc(fd, next);
            fprintf(stderr, "Corruption : chaine vers bloc libre %u\n", next);
            free(buf);
            return NULL;
        }

        a = reste > OBJ_SIZE ? OBJ_SIZE : reste;
        memcpy(buf + copies, t[next].obj, a);
        copies += a;
        reste -= a;
        precedent = next;
        next = t[next].suivant;
        deverr_bloc(fd, precedent);
    }

    buf[total] = 0;
    *taille_out = total;
    if (suivant_out) *suivant_out = next;
    return buf;
}

/* Vérifie la table, pour chaque objet, recalcule le hash de son contenu et vérifie qu'il est à l'emplacement attendu via premier(). */
void commande_check(const char *fname) {
    uint32_t b; int fd; size_t sz;
    struct hache_entree *t = ouvrir_table(fname, &b, &fd, &sz);
    uint32_t err = 0, vus = 0;
   
    uint32_t *vu = calloc(b, sizeof *vu);
    if (!vu) {
        perror("calloc");
        fermer_table(t, fd, sz);
        exit(EXIT_FAILURE);
    }

    for (uint32_t h = 0; h < b; h++) {
        verr_bloc(fd, h, F_RDLCK);
        uint32_t cur = t[h].premier;
        deverr_bloc(fd, h);
        if (cur == BLOC_CONS) 
            continue;

        if (cur >= b) {
            fprintf(stderr, "Corruption : premier(%u) invalide %u\n", h, cur);
            err++;
            continue;
        }

        while (cur != BLOC_CONS) {
            if (cur >= b) {
                fprintf(stderr, "Corruption : bloc de collision invalide %u pour h=%u\n", cur, h);
                err++;
                break;
            }
            if (vu[cur] == h + 1) {
                fprintf(stderr, "Corruption : boucle dans la chaine de h=%u au bloc %u\n", h, cur);
                err++;
                break;
            }
            vu[cur] = h + 1;

            verr_bloc(fd, cur, F_RDLCK);
            if (t[cur].longueur == BLOC_CONS) { 
                deverr_bloc(fd, cur); 
                if (cur == h)
                    break;
                fprintf(stderr, "Corruption : chaine vers bloc libre %u pour h=%u\n", cur, h);
                err++;
                break; 
            }

            size_t taille;
            uint32_t type;
            uint32_t suiv = BLOC_CONS;
            char *buf = lire_objet_check(t, fd, b, cur, &taille, &type, &suiv);
            deverr_bloc(fd, cur);
            if (!buf) {
                err++;
                break;
            }

            uint32_t hh = calculer_hash(fname, (uint8_t *)buf, taille, b);
            if (hh != h) {
                fprintf(stderr, "Corruption : objet a cur=%u attendu h=%u, calcule %u\n", cur, h, hh);
                err++;
            }
            free(buf);
            vus++;

            if (suiv != BLOC_CONS && suiv >= b) {
                fprintf(stderr, "Corruption : objet suivant invalide %u apres %u\n", suiv, cur);
                err++;
                break;
            }
            cur = suiv;
        }
    }
    free(vu);
    printf("check : %u objets verifies, %u erreur(s)\n", vus, err);
    fermer_table(t, fd, sz);
    if (err) 
        exit(EXIT_FAILURE);
}

/* Insertion d'un fichier */
void commande_insertfile(const char *fname_table, const char *fname_src) {
    int sfd = open(fname_src, O_RDONLY);
    if (sfd == -1) { 
        perror("open source"); 
        exit(EXIT_FAILURE);
    }

    struct stat ss;
    if (fstat(sfd, &ss) == -1) { /* Récup des métadonnées du fichier */
        perror("fstat source"); 
        close(sfd); 
        exit(EXIT_FAILURE); 
    }

    size_t taille_contenu = (size_t)ss.st_size;
    void *src = NULL;

    if (taille_contenu > 0) {
        src = mmap(NULL, taille_contenu, PROT_READ, MAP_PRIVATE, sfd, 0);
        if (src == MAP_FAILED) { 
            perror("mmap source"); 
            close(sfd); 
            exit(EXIT_FAILURE); 
        }
    }

    char *bn_copy = strdup(fname_src);
    char *bn = basename(bn_copy);
    uint32_t nom_len = (uint32_t)strlen(bn);

    /* Construction des métadonnées */
    struct meta_fichier mf;
    mf.taille = taille_contenu;
    mf.mtime = (int64_t)ss.st_mtime;
    mf.mode = (uint32_t)ss.st_mode;
    mf.nom_len = nom_len;

    size_t total = sizeof(mf) + nom_len + taille_contenu;
    char *buf = malloc(total);
    if (!buf) { 
        perror("malloc"); 
        exit(EXIT_FAILURE); 
    }

    memcpy(buf, &mf, sizeof(mf));
    memcpy(buf + sizeof(mf), bn, nom_len);
    if (taille_contenu) 
        memcpy(buf + sizeof(mf) + nom_len, src, taille_contenu);

    if (src) 
        munmap(src, taille_contenu);

    close(sfd);
    free(bn_copy);

    uint32_t b; int fd; size_t sz;
    struct hache_entree *t = ouvrir_table(fname_table, &b, &fd, &sz);
    uint32_t h = calculer_hash(fname_table, (uint8_t *)buf, total, b);

    verr_bloc(fd, h, F_WRLCK);
    uint32_t tete = t[h].premier;

    /* Cas de base */
    if (tete == h && t[h].longueur == BLOC_CONS) {
        t[h].longueur = 0;
        if (ecrire_objet(t, b, fd, h, TYPE_FILE, buf, total, BLOC_CONS) == -1) {
            free(buf); 
            fermer_table(t, fd, sz); 
            exit(EXIT_FAILURE);
        }
        free(buf); 
        fermer_table(t, fd, sz); 
        return;
    }

    /* Cas ou rien n'est encore associer au hash*/
    if (tete == BLOC_CONS) {
        uint32_t nv = reserver_bloc_libre(t, b, fd, h);
        if (nv == BLOC_CONS) {
            deverr_bloc(fd, h);
            fprintf(stderr, "Erreur : table pleine\n");
            free(buf); 
            fermer_table(t, fd, sz); 
            exit(EXIT_FAILURE);
        }

        if (t[nv].premier == nv) 
            t[nv].premier = BLOC_CONS;

        if (ecrire_objet(t, b, fd, nv, TYPE_FILE, buf, total, h) == -1) {
            deverr_bloc(fd, h);
            free(buf); 
            fermer_table(t, fd, sz); 
            exit(EXIT_FAILURE);
        }

        /* Maj du debut de chane */
        t[h].premier = nv;
        deverr_bloc(fd, h);
        free(buf); 
        fermer_table(t, fd, sz); 
        return;
    }

    /* Collision donc le parcour de la chaîne */
    uint32_t cur = tete;
    int doublon = 0;
    uint32_t dernier = BLOC_CONS;

    /* Change de verrou si le premier objet n'est pas h */
    if (cur != h)
        verr_bloc(fd, cur, F_RDLCK);

    while (1) {
        if (t[cur].type == TYPE_FILE && comparer_objet(t, fd, cur, buf, total))
            doublon = 1;

        /* Passe les blocs internes du même fichier */
        size_t reste = t[cur].longueur;
        uint32_t suiv = t[cur].suivant;
        uint32_t fin = cur;
        if (cur != h) 
            deverr_bloc(fd, cur);

        while (reste > OBJ_SIZE && suiv != BLOC_CONS) {
            reste -= OBJ_SIZE;
            if (suiv != h) 
                verr_bloc(fd, suiv, F_RDLCK);

            fin = suiv;
            uint32_t s = t[suiv].suivant;
            if (suiv != h) 
                deverr_bloc(fd, suiv);

            suiv = s;
        }

        /* Dernier bloc du fichier courant */
        dernier = fin;
        if (suiv == BLOC_CONS) 
            break;

        if (suiv != h) 
            verr_bloc(fd, suiv, F_RDLCK);
        cur = suiv;
    }

    if (doublon) {
        deverr_bloc(fd, h);
        fprintf(stderr, "Warning : fichier deja present (mêmes meta+contenu), table inchangee\n");
        free(buf); 
        fermer_table(t, fd, sz); 
        return;
    }

    /* Ajout du fichier à la fin de la chaîne */
    uint32_t nv = reserver_bloc_libre(t, b, fd, h);
    if (nv == BLOC_CONS) {
        deverr_bloc(fd, h);
        fprintf(stderr, "Erreur : table pleine\n");
        free(buf); 
        fermer_table(t, fd, sz); 
        exit(EXIT_FAILURE);
    }

    if (t[nv].premier == nv) 
        t[nv].premier = BLOC_CONS;

    /* Chaînage vers le nouveau fichier */
    if (dernier != h) 
        verr_bloc(fd, dernier, F_WRLCK);

    t[dernier].suivant = nv;
    if (dernier != h) 
        deverr_bloc(fd, dernier);

    if (ecrire_objet(t, b, fd, nv, TYPE_FILE, buf, total, h) == -1) {
        deverr_bloc(fd, h);
        free(buf); 
        fermer_table(t, fd, sz); 
        exit(EXIT_FAILURE);
    }
    deverr_bloc(fd, h);
    free(buf);
    fermer_table(t, fd, sz);
}

/* Délimitaion des zone de thread avec traitement */
void *thread_zone(void *p) {
    struct zone_arg *z = (struct zone_arg *)p;
    size_t pos;

    /* Cherche le début de la ligne possédée par cette zone, si on détecte pas de \n c'est qu'il appartient au thread précedent donc on continue jusqu'au prochaine "\," */
    if (z->debut == 0 || z->src[z->debut - 1] == '\n') {
        pos = z->debut;
    } else {
        pos = z->debut;
        while (pos < z->taille && z->src[pos] != '\n')
            pos++;
        if (pos < z->taille) pos++;
    }

    /* Traite les lignes qui commencent avant la fin de la zone, si débordement on le considère a lui */
    while (pos < z->fin && pos < z->taille) {
        size_t deb = pos;
        while (pos < z->taille && z->src[pos] != '\n')
            pos++;
        size_t len = pos - deb;
        if (len > 0) {
            uint32_t h = calculer_hash(z->fname, (const uint8_t *)(z->src + deb), len, z->b);
            pthread_mutex_lock(&G_hash_mutex[h % NHASH_MUTEX]);
            inserer_chaine(z->t, z->b, z->fd, z->fname, TYPE_STRING, z->src + deb, len);
            pthread_mutex_unlock(&G_hash_mutex[h % NHASH_MUTEX]);
        }
        if (pos < z->taille) pos++;
    }
    return NULL;
}

/* Insertion par ligne  */
void commande_insertlines(const char *fname_table, const char *fname_src) {
    int sfd = open(fname_src, O_RDONLY);
    if (sfd == -1) {
        perror("open source");
        exit(EXIT_FAILURE);
    }
    struct stat ss;
    if (fstat(sfd, &ss) == -1) {
        perror("fstat source");
        close(sfd);
        exit(EXIT_FAILURE);
    }
    size_t taille = (size_t)ss.st_size;
    if (taille == 0) {
        close(sfd);
        return;
    }
    char *src = mmap(NULL, taille, PROT_READ, MAP_PRIVATE, sfd, 0);
    if (src == MAP_FAILED) {
        perror("mmap source");
        close(sfd);
        exit(EXIT_FAILURE);
    }

    long nth = sysconf(_SC_NPROCESSORS_ONLN);
    if (nth < 1) 
        nth = 1;
    if ((size_t)nth > taille) 
        nth = (long)taille;

    uint32_t b; int fd; size_t sz;
    struct hache_entree *t = ouvrir_table(fname_table, &b, &fd, &sz);

    pthread_t *th = malloc(sizeof(pthread_t) * nth);
    struct zone_arg *args = malloc(sizeof(struct zone_arg) * nth);
    if (!th || !args) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }

    size_t zsize = taille / nth;
    for (long i = 0; i < nth; i++) {
        args[i].src = src;
        args[i].taille = taille;
        args[i].debut = (size_t)i * zsize;
        args[i].fin = (i == nth - 1) ? taille : (size_t)(i + 1) * zsize;
        args[i].t = t;
        args[i].b = b;
        args[i].fd = fd;
        args[i].fname = fname_table;
        if (pthread_create(&th[i], NULL, thread_zone, &args[i]) != 0) {
            perror("pthread_create");
            exit(EXIT_FAILURE);
        }
    }
    for (long i = 0; i < nth; i++)
        pthread_join(th[i], NULL);

    free(th);
    free(args);
    fermer_table(t, fd, sz);
    munmap(src, taille);
    close(sfd);
}

/* Recrée la table avec "new_b" bloc en faisant une vérif total des hash puis suppr l'ancien fichier pour le remplacer */   
void redim_table(const char *fname, uint32_t new_b) {
    if (new_b == 0) {
        fprintf(stderr, "Erreur : redimensionnement vers 0 bloc impossible\n");
        exit(EXIT_FAILURE);
    }

    uint32_t b; int fd; size_t sz;
    struct hache_entree *t = ouvrir_table(fname, &b, &fd, &sz);

    char tmp[4096];
    snprintf(tmp, sizeof tmp, "%s.tmp", fname);
    commande_make(tmp, new_b);

    uint32_t nb; int nfd; size_t nsz;
    struct hache_entree *nt = ouvrir_table(tmp, &nb, &nfd, &nsz);

    int plein = 0;
    for (uint32_t h = 0; h < b && !plein; h++) {
        verr_bloc(fd, h, F_RDLCK);
        uint32_t cur = t[h].premier;
        deverr_bloc(fd, h);
        if (cur == BLOC_CONS) 
            continue;

        while (cur != BLOC_CONS) {
            verr_bloc(fd, cur, F_RDLCK);
            if (t[cur].longueur == BLOC_CONS) { 
                deverr_bloc(fd, cur); 
                break; 
            }

            size_t tl; uint32_t ty;
            char *buf = lire_objet(t, fd, cur, &tl, &ty);
            size_t reste = t[cur].longueur;
            uint32_t suiv = t[cur].suivant;
            deverr_bloc(fd, cur);
            while (reste > OBJ_SIZE && suiv != BLOC_CONS) {
                reste -= OBJ_SIZE;
                verr_bloc(fd, suiv, F_RDLCK);
                uint32_t s = t[suiv].suivant;
                deverr_bloc(fd, suiv);
                suiv = s;
            }
            if (buf) {
                int r = inserer_chaine(nt, nb, nfd, fname, ty, buf, tl);
                free(buf);
                if (r == -1) { 
                    plein = 1; 
                    break; 
                }
            }
            cur = suiv;
        }
    }

    fermer_table(nt, nfd, nsz);
    fermer_table(t, fd, sz);

    if (plein) {
        unlink(tmp);
        fprintf(stderr, "Erreur : redimensionnement impossible (table trop petite)\n");
        exit(EXIT_FAILURE);
    }
    if (rename(tmp, fname) == -1) {
        perror("rename");
        unlink(tmp);
        exit(EXIT_FAILURE);
    }
}

/* Double la taille */
void commande_extend(const char *fname) {
    uint32_t b; int fd; size_t sz;
    struct hache_entree *t = ouvrir_table(fname, &b, &fd, &sz);
    fermer_table(t, fd, sz);
    if ((uint64_t)b * 2 > 0xFFFFFFFFUL) {
        fprintf(stderr, "Erreur : extend dépasse 2^32 blocs\n");
        exit(EXIT_FAILURE);
    }
    redim_table(fname, b * 2);
}

/* Divise la taille par deux */
void commande_shrink(const char *fname) {
    uint32_t b; int fd; size_t sz;
    struct hache_entree *t = ouvrir_table(fname, &b, &fd, &sz);
    fermer_table(t, fd, sz);
    if (b / 2 == 0) {
        fprintf(stderr, "Erreur : impossible de réduire (b=%u)\n", b);
        exit(EXIT_FAILURE);
    }
    redim_table(fname, b / 2);
}

/* Augmente si + de 70% de remp ou réduit si besoin (- de 10% de remp) */
void commande_ajust(const char *fname) {
    uint32_t b; int fd; size_t sz;
    struct hache_entree *t = ouvrir_table(fname, &b, &fd, &sz);
    uint32_t occ = 0;
    for (uint32_t i = 0; i < b; i++) {
        verr_bloc(fd, i, F_RDLCK);
        if (t[i].longueur != BLOC_CONS) 
            occ++;
        deverr_bloc(fd, i);
    }
    fermer_table(t, fd, sz);
    double taux = ((double)occ / b) * 100.0;
    if (taux > 70.0 && (uint64_t)b * 2 <= 0xFFFFFFFFUL)
        redim_table(fname, b * 2);
    else if (taux < 10.0 && b / 2 >= 1)
        redim_table(fname, b / 2);
}

/* Format : hachement <commande> <table> <slowns> [args...], le parsing pour la ligne de commande */
int main(int argc, char *argv[]) {
    init_mutexes();
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <commande> <table> <slowns> [args...]\n", argv[0]);
        fprintf(stderr, "Commandes : make | free | insertstring | insertfile | lookup | deletehash | delete | check | insertlines\n");
        return EXIT_FAILURE;
    }

    if (!strcmp(argv[1], "make")) {
        if (argc != 5) {
            fprintf(stderr, "Usage: %s make <table> <slowns> <b>\n", argv[0]);
            return EXIT_FAILURE;
        }
        G_slowns = (uint64_t)strtoull(argv[3], NULL, 10);
        uint32_t bb = (uint32_t)strtoul(argv[4], NULL, 10);
        commande_make(argv[2], bb);
    } else if (!strcmp(argv[1], "free")) {
        if (argc != 4) {
            fprintf(stderr, "Usage: %s free <table> <slowns>\n", argv[0]);
            return EXIT_FAILURE;
        }
        G_slowns = (uint64_t)strtoull(argv[3], NULL, 10);
        commande_free(argv[2]);
    } else if (!strcmp(argv[1], "insertstring")) {
        if (argc != 5) {
            fprintf(stderr, "Usage: %s insertstring <table> <slowns> <chaine>\n", argv[0]);
            return EXIT_FAILURE;
        }
        G_slowns = (uint64_t)strtoull(argv[3], NULL, 10);
        commande_insertstring(argv[2], argv[4]);
    } else if (!strcmp(argv[1], "insertfile")) {
        if (argc != 5) {
            fprintf(stderr, "Usage: %s insertfile <table> <slowns> <fichier>\n", argv[0]);
            return EXIT_FAILURE;
        }
        G_slowns = (uint64_t)strtoull(argv[3], NULL, 10);
        commande_insertfile(argv[2], argv[4]);
    } else if (!strcmp(argv[1], "lookup")) {
        if (argc != 5) {
            fprintf(stderr, "Usage: %s lookup <table> <slowns> <chaine|nom>\n", argv[0]);
            return EXIT_FAILURE;
        }
        G_slowns = (uint64_t)strtoull(argv[3], NULL, 10);
        commande_lookup(argv[2], argv[4]);
    } else if (!strcmp(argv[1], "deletehash")) {
        if (argc != 5) {
            fprintf(stderr, "Usage: %s deletehash <table> <slowns> <hash>\n", argv[0]);
            return EXIT_FAILURE;
        }
        G_slowns = (uint64_t)strtoull(argv[3], NULL, 10);
        uint32_t hh;
        const char *s = argv[4];
        if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) hh = (uint32_t)strtoul(s, NULL, 16);
        else hh = (uint32_t)strtoul(s, NULL, 10);
        commande_deletehash(argv[2], hh);
    } else if (!strcmp(argv[1], "delete")) {
        if (argc != 5) {
            fprintf(stderr, "Usage: %s delete <table> <slowns> <chaine>\n", argv[0]);
            return EXIT_FAILURE;
        }
        G_slowns = (uint64_t)strtoull(argv[3], NULL, 10);
        commande_delete(argv[2], argv[4]);
    } else if (!strcmp(argv[1], "check")) {
        if (argc != 4) {
            fprintf(stderr, "Usage: %s check <table> <slowns>\n", argv[0]);
            return EXIT_FAILURE;
        }
        G_slowns = (uint64_t)strtoull(argv[3], NULL, 10);
        commande_check(argv[2]);
    } else if (!strcmp(argv[1], "insertlines")) {
        if (argc != 5) {
            fprintf(stderr, "Usage: %s insertlines <table> <slowns> <fichier>\n", argv[0]);
            return EXIT_FAILURE;
        }
        G_slowns = (uint64_t)strtoull(argv[3], NULL, 10);
        commande_insertlines(argv[2], argv[4]);
    } else if (!strcmp(argv[1], "extend")) {
        if (argc != 4) {
            fprintf(stderr, "Usage: %s extend <table> <slowns>\n", argv[0]);
            return EXIT_FAILURE;
        }
        G_slowns = (uint64_t)strtoull(argv[3], NULL, 10);
        commande_extend(argv[2]);
    } else if (!strcmp(argv[1], "shrink")) {
        if (argc != 4) {
            fprintf(stderr, "Usage: %s shrink <table> <slowns>\n", argv[0]);
            return EXIT_FAILURE;
        }
        G_slowns = (uint64_t)strtoull(argv[3], NULL, 10);
        commande_shrink(argv[2]);
    } else if (!strcmp(argv[1], "ajust")) {
        if (argc != 4) {
            fprintf(stderr, "Usage: %s ajust <table> <slowns>\n", argv[0]);
            return EXIT_FAILURE;
        }
        G_slowns = (uint64_t)strtoull(argv[3], NULL, 10);
        commande_ajust(argv[2]);
    } else {
        fprintf(stderr, "Commande inconnue : %s\n", argv[1]);
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}