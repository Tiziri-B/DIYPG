#include <stdio.h>
#include <stdint.h>
#include <sys/stat.h>      // chmod
#include "storage.h"
#include "affichage.h"
#include "pubkey_io.h"
#include "rsa_keys.h"      


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

    if (fclose(f) != 0) {
        aff_erreur("save : erreur d'ecriture dans '%s'\n", path);
        return -1;
    }

    return 0;
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

    char id[NAME_MAX_SIZE];  
    char type[TYPE_MAX_SIZE];
    
    unsigned long long pubE, pubN, privE, privN;
    int lu;

    while ((lu = fscanf(f, "%31s %7s %llu %llu %llu %llu", id, type, &pubE, &pubN, &privE, &privN)) == 6) {
        keyPair_t paire;
        paire.pubKey.E = pubE;
        paire.pubKey.N = pubN;
        paire.privKey.E = privE;
        paire.privKey.N = privN;

        // verifier la cle
        if (!keyCheckBlock(&paire.pubKey, &paire.privKey)) {
            aff_erreur("load : la clef '%s' est incorrecte\n", id);
            fclose(f);
            keyring_free(&nouveau);
            return -1;
        }

        // creation de l'entree et verification + doublons
        int r = keyring_new(&nouveau, id, type);
        if (r != KR_OK) {
            aff_erreur("load : la clef '%s' est refusee (%s)\n", id, keyring_erreur(r));
            fclose(f);
            keyring_free(&nouveau);
            return -1;
        }

        keyring_find(&nouveau, id)->keys = paire;

    }
    fclose(f);
    
    // une ligne est abimee
    if (lu != EOF) {
        aff_erreur("load : le fichier '%s' est abime (ligne incorrecte)\n", path);
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

    KeyEntry *e = keyring_find(kr, keyid);
    if (e == NULL) {
        aff_erreur("savepub : %s\n", keyring_erreur(KR_ERR_NOTFOUND));
        return -1;
    }
   
    return pubkey_export(path, &e->keys.pubKey); 
}
