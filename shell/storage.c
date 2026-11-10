#include <stdio.h>
#include <stdint.h>
#include <sys/stat.h>      // chmod
#include "storage.h"
#include "affichage.h"
#include "pubkey_io.h"
#include "rsa_keys.h"
#include <string.h>
#include "contacts.h"


int storage_save(const KeyRing *kr, const char *path) {
    if (kr == NULL) return -1;
    if (path == NULL) path = FICHIER_PAR_DEFAUT;

    FILE *f = fopen(path, "w");
    if (f == NULL) {
        aff_erreur("save : impossible de creer le fichier '%s'\n", path);
        return -1;
    }
    chmod(path, 0600);

    for (int i = 0; i < kr->count; i++) {
        const KeyEntry *e = &kr->entries[i];
        fprintf(f, "%s %s %llu %llu %llu %llu\n", e->id, e->type,
                (unsigned long long) e->keys.pubKey.E, (unsigned long long) e->keys.pubKey.N,
                (unsigned long long) e->keys.privKey.E, (unsigned long long) e->keys.privKey.N);
    }

    /* Les contacts sont sauvegardes avec des lignes identifiees par CONTACT
       et CONTACTKEY. Le separateur | est interdit dans les champs texte. */
    for (int i = 0; i < kr->nb_contacts; i++) {
        const Contact *c = &kr->contacts[i];
        fprintf(f, "CONTACT|%s|%s|%s|%s\n", c->id, c->nom, c->prenom, c->commentaire);
        for (int j = 0; j < c->nb_cles; j++) {
            const ContactKey *k = &c->cles[j];
            fprintf(f, "CONTACTKEY|%s|%s|%s|%llu|%llu\n", c->id, k->id, k->type,
                    (unsigned long long)k->pubKey.E, (unsigned long long)k->pubKey.N);
        }
    }

    if (fclose(f) != 0) {
        aff_erreur("save : erreur d'ecriture dans '%s'\n", path);
        return -1;
    }

    return 0;
}

// une ligne de clef de l'utilisateur : "id type pubE pubN privE privN"
static int lire_cle(KeyRing *kr, const char *ligne) {
    char id[NAME_MAX_SIZE], type[TYPE_MAX_SIZE], extra;
    unsigned long long pubE, pubN, privE, privN;
    if (sscanf(ligne, "%31s %7s %llu %llu %llu %llu %c", id, type, &pubE, &pubN, &privE, &privN, &extra) != 6) return -1;

    keyPair_t paire;
    paire.pubKey.E = pubE;  paire.pubKey.N = pubN;
    paire.privKey.E = privE; paire.privKey.N = privN;
    if (!keyCheckBlock(&paire.pubKey, &paire.privKey) && !keyCheck(&paire.pubKey, &paire.privKey)) return -1;

    if (keyring_new(kr, id, type) != KR_OK) return -1;
    keyring_find(kr, id)->keys = paire;
    return 0;
}

// une ligne de contact : "CONTACT|id|nom|prenom|commentaire" (les champs texte peuvent etre vides)
static int lire_contact(KeyRing *kr, char *ligne) {
    char *champs[5];
    int nb = 0;
    char *p = ligne;
    while (p != NULL && nb < 5) {      // on coupe la ligne sur les '|'
        champs[nb++] = p;
        p = strchr(p, '|');
        if (p != NULL) *p++ = '\0';
    }
    if (nb != 5 || p != NULL) return -1;   // il faut exactement 5 champs
    return contact_add(kr, champs[1], champs[2], champs[3], champs[4]);
}

// une ligne de clef de contact : "CONTACTKEY|idcontact|idclef|type|E|N"
static int lire_cle_contact(KeyRing *kr, const char *ligne) {
    char id_contact[NAME_MAX_SIZE], id_clef[NAME_MAX_SIZE], type[TYPE_MAX_SIZE], extra;
    unsigned long long E, N;
    if (sscanf(ligne, "CONTACTKEY|%31[^|]|%31[^|]|%7[^|]|%llu|%llu%c",
               id_contact, id_clef, type, &E, &N, &extra) != 5) return -1;
    rsaKey_t pub;
    pub.E = E;
    pub.N = N;
    return contact_addkey(kr, id_contact, id_clef, type, &pub);
}

int storage_load(KeyRing *kr, const char *path) {
    if (kr == NULL) return -1;
    if (path == NULL) path = FICHIER_PAR_DEFAUT;

    FILE *f = fopen(path, "r");
    if (f == NULL) {
        aff_erreur("load : impossible de lire le fichier '%s'\n", path);
        return -1;
    }

    KeyRing nouveau;
    keyring_init(&nouveau);

    char ligne[512];
    int r = 0;
    while (r == 0 && fgets(ligne, sizeof ligne, f) != NULL) {
        ligne[strcspn(ligne, "\n")] = '\0';     // on enleve le '\n'
        if (strncmp(ligne, "CONTACTKEY|", 11) == 0) r = lire_cle_contact(&nouveau, ligne);
        else if (strncmp(ligne, "CONTACT|", 8) == 0) r = lire_contact(&nouveau, ligne);
        else r = lire_cle(&nouveau, ligne);
    }
    if (ferror(f)) r = -1;
    fclose(f);

    if (r != 0) {
        aff_erreur("load : le fichier '%s' est abime ou contient une entree invalide\n", path);
        keyring_free(&nouveau);
        return -1;
    }

    // tout est bon
    keyring_free(kr);
    *kr = nouveau;
    return 0;
}

int storage_savepub(KeyRing *kr, const char *keyid, const char *path) {
    if (kr == NULL || keyid == NULL || path == NULL) return -1;

    const rsaKey_t *pub = NULL;
    if (strchr(keyid, '/') != NULL) {          // clef d'un contact : idcontact/idclef
        ContactKey *k = contact_findkey(kr, keyid);
        if (k != NULL) pub = &k->pubKey;
    } else {                                   // clef de l'utilisateur
        KeyEntry *e = keyring_find(kr, keyid);
        if (e != NULL) pub = &e->keys.pubKey;
    }

    if (pub == NULL) {
        aff_erreur("savepub : %s\n", keyring_erreur(KR_ERR_NOTFOUND));
        return -1;
    }
    return pubkey_export(path, pub);
}
