#include <stdio.h>
#include "rsa_keyio.h"

FILE *logfp = NULL;


int main(void) {
    
    rsaKey_t pub_orig  = { .E = 7,     .N = 97343 };
    rsaKey_t priv_orig = { .E = 82903, .N = 97343 };

    /* 2. Clés réceptrices pour le rechargement */
    rsaKey_t pub_lue   = { 0, 0 };
    rsaKey_t priv_lue  = { 0, 0 };

    const char *path = "/tmp/diypg_test_keys.bin";
    int erreurs = 0;

    /* Sauvegarde avec 3 arguments */
    if (key_save(path, &pub_orig, &priv_orig) != 0) {
        printf("ECHEC : key_save\n");
        erreurs++;
    }

    /* Chargement avec 3 arguments */
    if (key_load(path, &pub_lue, &priv_lue) != 0) {
        printf("ECHEC : key_load\n");
        erreurs++;
    }

    /* Vérification des données rechargées */
    if (pub_orig.E != pub_lue.E || pub_orig.N != pub_lue.N
        || priv_orig.E != priv_lue.E || priv_orig.N != priv_lue.N) {
        printf("ECHEC : la paire rechargee est differente\n");
        erreurs++;
    }

    /* Test de robustesse : fichier inexistant */
    if (key_load("/tmp/fichier_qui_nexiste_pas.bin", &pub_lue, &priv_lue) == 0) {
        printf("ECHEC : charger un fichier absent devrait echouer\n");
        erreurs++;
    }

    /* Test de robustesse : pointeur NULL */
    if (key_save(NULL, &pub_orig, &priv_orig) == 0) {
        printf("ECHEC : sauvegarder avec path NULL devrait echouer\n");
        erreurs++;
    }

    remove(path);

    if (erreurs == 0) {
        printf("OK : key_save / key_load\n");
    }
    return erreurs != 0;
}