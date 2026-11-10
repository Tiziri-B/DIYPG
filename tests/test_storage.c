#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include "../shell/storage.h"
#include "pubkey_io.h"
#include "rsa_keys.h"
#include "check.h"

// si les deux annuaires contiennent les memes cles dans le meme ordre
static int memes_annuaires(const KeyRing *a, const KeyRing *b){
    if (a->count != b->count) return 0;
    for (int i = 0; i < a->count; i++) {
        const KeyEntry *x = &a->entries[i];
        const KeyEntry *y = &b->entries[i];
        if (strcmp(x->id, y->id) != 0 || strcmp(x->type, y->type) != 0
            || x->keys.pubKey.E != y->keys.pubKey.E || x->keys.pubKey.N != y->keys.pubKey.N
            || x->keys.privKey.E != y->keys.privKey.E || x->keys.privKey.N != y->keys.privKey.N) return 0;
    }
    return 1;
}

// ecrit un texte dans un fichier
static void ecrire_fichier(const char *chemin, const char *texte) {
    FILE *f = fopen(chemin, "w");
    fputs(texte, f);
    fclose(f);
}

// ecrit dans ligne : "id type E N E N" avec ces clefs
static void faire_ligne(char *ligne, const char *id, const char *type, keyPair_t k) {
    sprintf(ligne, "%s %s %llu %llu %llu %llu\n", id, type,
            (unsigned long long) k.pubKey.E, (unsigned long long) k.pubKey.N,
            (unsigned long long) k.privKey.E, (unsigned long long) k.privKey.N);
}

// retourne 1 si load echoue et l'annuaire ne change pas
static int load_refuse(const char *chemin) {
    KeyRing kr;
    keyring_init(&kr);
    keyring_new(&kr, "fixe", KEY_TYPE_CRYPT);
    int r = storage_load(&kr, chemin);
    int inchange = kr.count == 1 && keyring_find(&kr, "fixe") != NULL;
    keyring_free(&kr);
    return r == -1 && inchange;
}

int main(void) {
    srand(2026);
    const char *f = "build/storage_test.dat";
    struct stat st;

    KeyRing kr;
    keyring_init(&kr);
    keyring_new(&kr, "perso", KEY_TYPE_CRYPT);
    keyring_new(&kr, "boulot", KEY_TYPE_CRYPT);
    keyring_new(&kr, "signature", KEY_TYPE_SIGN);

    printf("***** save puis load *****\n");
    verifier("save reussit", storage_save(&kr, f) == 0);
   verifier("le fichier de sauvegarde a bien ete cree", stat(f, &st) == 0);

    KeyRing kr2;
    keyring_init(&kr2);
    verifier("load reussit", storage_load(&kr2, f) == 0);
    verifier("les 3 cles sont retrouvees a l'identique", memes_annuaires(&kr, &kr2));
    verifier("le type est retrouve", keyring_find(&kr2, "signature") != NULL && strcmp(keyring_find(&kr2, "signature")->type, KEY_TYPE_SIGN) == 0);


    printf("\n***** load remplace l'annuaire existant *****\n");
    KeyRing kr3;
    keyring_init(&kr3);
    keyring_new(&kr3, "autre", KEY_TYPE_CRYPT);
    verifier("load reussit", storage_load(&kr3, f) == 0);
    verifier("l'ancienne cle 'autre' a disparu", keyring_find(&kr3, "autre") == NULL);
    verifier("annuaire = celui du fichier", memes_annuaires(&kr, &kr3));
    keyring_free(&kr3);


    printf("\n***** annuaire vide *****\n");
    KeyRing vide;
    keyring_init(&vide);
    verifier("save d'un annuaire vide", storage_save(&vide, f) == 0);
    verifier("load donne un annuaire vide", storage_load(&kr2, f) == 0 && kr2.count == 0);
    keyring_free(&vide);


    printf("\n***** fichiers incorrects *****\n"); //l'annuaire ne change pas 
    verifier("fichier absent", load_refuse("build/n_existe_pas.dat"));
    ecrire_fichier(f, "n'importe quoi\n");
    verifier("texte quelconque", load_refuse(f));
    ecrire_fichier(f, "tiziri crypt 65537\n");
    verifier("ligne incomplete", load_refuse(f));

    keyPair_t k;
    generateKeysBlock(&k.pubKey, &k.privKey);
    char ligne[300], deux[600];

    faire_ligne(ligne, "tiziri", "truc", k);
    ecrire_fichier(f, ligne);
    verifier("type inconnu (truc)", load_refuse(f));

    keyPair_t mauvaise = k;
    mauvaise.privKey.E = k.privKey.E + 2;
    faire_ligne(ligne, "tiziri", KEY_TYPE_CRYPT, mauvaise);
    ecrire_fichier(f, ligne);
    verifier("paire de cles qui ne marche pas", load_refuse(f));

    keyPair_t petite;
    petite.pubKey.E = 3;
    petite.pubKey.N = 33;       
    petite.privKey.E = 7;
    petite.privKey.N = 33;
    faire_ligne(ligne, "tiziri", KEY_TYPE_CRYPT, petite);
    ecrire_fichier(f, ligne);
    verifier("cles avec N trop petit", load_refuse(f));

    faire_ligne(ligne, "tiziri", KEY_TYPE_CRYPT, k);
    strcpy(deux, ligne);
    strcat(deux, ligne);
    ecrire_fichier(f, deux);
    verifier("meme identifiant deux fois", load_refuse(f));

    faire_ligne(ligne, "a/b", KEY_TYPE_CRYPT, k);
    ecrire_fichier(f, ligne);
    verifier("identifiant avec un '/'", load_refuse(f));

    faire_ligne(ligne, "un_identifiant_beaucoup_trop_long_pour_etre_accepte", KEY_TYPE_CRYPT, k);
    ecrire_fichier(f, ligne);
    verifier("identifiant de plus de 31 caracteres", load_refuse(f));


    printf("\n***** save sur un fichier existant *****\n");
    ecrire_fichier(f, "ancien contenu bien plus long que le nouveau, lisible par tout le monde\n");
    chmod(f, 0644);
    verifier("save reussit", storage_save(&kr, f) == 0);
    verifier("le fichier de sauvegarde a bien ete cree", stat(f, &st) == 0);
    KeyRing kr4;
    keyring_init(&kr4);
    verifier("l'ancien contenu a disparu", storage_load(&kr4, f) == 0 && memes_annuaires(&kr, &kr4));
    keyring_free(&kr4);


    printf("\n***** savepub *****\n");
    const char *p = "build/storage_pub.txt";
    rsaKey_t lue;
    verifier("savepub reussit", storage_savepub(&kr, "perso", p) == 0);
    verifier("pubkey_import relit la cle publique de 'perso'",
          pubkey_import(p, &lue) == 0 && lue.E == keyring_find(&kr, "perso")->keys.pubKey.E
          && lue.N == keyring_find(&kr, "perso")->keys.pubKey.N);
    verifier("identifiant inconnu refuse", storage_savepub(&kr, "inconnu", p) == -1);
    verifier("dossier inexistant refuse", storage_savepub(&kr, "perso", "build/pas_de_dossier/k.txt") == -1);
    verifier("NULL refuses", storage_savepub(NULL, "perso", p) == -1 && storage_savepub(&kr, NULL, p) == -1
                          && storage_savepub(&kr, "perso", NULL) == -1
                          && storage_save(NULL, f) == -1 && storage_load(NULL, f) == -1);
    
    
    printf("\n***** fichier par defaut *****\n");
    remove(FICHIER_PAR_DEFAUT);
    KeyRing kr5;
    keyring_init(&kr5);
    verifier("save sans nom puis load sans nom",
        storage_save(&kr, NULL) == 0 && storage_load(&kr5, NULL) == 0 && memes_annuaires(&kr, &kr5));
    keyring_free(&kr5);
    remove(FICHIER_PAR_DEFAUT);

    keyring_free(&kr);
    keyring_free(&kr2);
    remove(f);
    remove(p);
    return nbEchecs;
}
