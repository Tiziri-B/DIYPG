#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pubkey_io.h"
#include "rsa_keys.h"
#include "io_utils.h"
#include "check.h"

static const char *FICHIER = "build/pubkey_test.txt";

// remplace le contenu du fichier de test par ce texte
// sert a fabriquer des fichiers abimes
static void ecrire_texte(const char *texte) {
    write_file(FICHIER, (const uint8_t *) texte, strlen(texte));
}

// exporte la cle puis la reimporte
// renvoie 1 si l'import reussit et redonne les memes E et N, 0 sinon
static int cle_acceptee(uint64_t E, uint64_t N) {
    rsaKey_t exp, imp;
    exp.E = E;
    exp.N = N;
    pubkey_export(FICHIER, &exp);
    return pubkey_import(FICHIER, &imp) == 0 && imp.E == E && imp.N == N;
}

// importe le fichier de test
// renvoie 1 si l'import est refuse et si la cle de depart n'a pas ete modifiee
static int import_refuse(void) {
    rsaKey_t k;
    k.E = 111;
    k.N = 222;
    int r = pubkey_import(FICHIER, &k);
    return r == -1 && k.E == 111 && k.N == 222;
}

static void test_aller_retour(void) {
    printf("\n***** Export puis import *****\n");
    verifier("cle simple : E = 65537, N = 2^32 + 1", cle_acceptee(65537, (1ULL << 32) + 1));

    // le fichier doit contenir 24 caracteres + le retour a la ligne
    char ligne[100];
    FILE *f = fopen(FICHIER, "r");
    fgets(ligne, sizeof ligne, f);
    fclose(f);
    verifier("le fichier contient 24 caracteres + retour a la ligne", strlen(ligne) == 25);

     // tester 50 cles
    int rates = 0;
    for (int i = 0; i < 50; i++) {
        rsaKey_t pub, priv;
        generateKeysBlock(&pub, &priv);
        if (!cle_acceptee(pub.E, pub.N)) rates++;
    }
    verifier("50 vraies cles : export puis import redonnent la meme cle", rates == 0);
}

static void test_limites(void) {
    printf("\n***** Cles inutilisables *****\n");
    verifier("N = 2^32 accepte (le plus petit N possible)", cle_acceptee(65537, 1ULL << 32));
    verifier("N = 2^32 - 1 refuse", !cle_acceptee(65537, (1ULL << 32) - 1));
    verifier("exemple de la phase 1 (E=3,N=33) refuse", !cle_acceptee(3, 33));
}

static void test_fichiers(void) {
    printf("\n***** Fichiers recus *****\n");

    // un mail peut ajouter des retours a la ligne et des espaces a la fin
    rsaKey_t pub, lue;
    pub.E = 65537;
    pub.N = (1ULL << 32) + 1;
    pubkey_export(FICHIER, &pub);
    FILE *f = fopen(FICHIER, "a");   
    fputs("\r\n  \n", f);
    fclose(f);
    verifier("retours a la ligne et espaces ajoutes : accepte",pubkey_import(FICHIER, &lue) == 0 && lue.E == pub.E && lue.N == pub.N);

    // fichiers incorrects : l'import doit les refuser sans modifier la cle
    remove(FICHIER);
    verifier("fichier absent : refuse", import_refuse());
    ecrire_texte("");
    verifier("fichier vide : refuse", import_refuse());
    ecrire_texte("ceci n'est pas du base64 !");
    verifier("texte qui n'est pas du base 64 : refuse", import_refuse());
    ecrire_texte("SGk=");   // "Hi" en base 64 :2 octets
    verifier("base 64 valide mais pas 16 octets : refuse", import_refuse());
}

static void test_erreurs(void) {
    printf("\n***** Erreurs *****\n");
    rsaKey_t pub, lue;
    pub.E = 65537;
    pub.N = (1ULL << 32) + 1;
    verifier("export dans un dossier inexistant : erreur",pubkey_export("build/pas_de_dossier/key.txt", &pub) == -1);

    verifier("pointeurs NULL : erreur",pubkey_export(NULL, &pub) == -1 && pubkey_export(FICHIER, NULL) == -1 && pubkey_import(NULL, &lue) == -1 && pubkey_import(FICHIER, NULL) == -1);
}

int main(void) {
    srand(2026);
    test_aller_retour();
    test_limites();
    test_fichiers();
    test_erreurs();
    remove(FICHIER);
    return nbEchecs;
}
 








