// tests de rsa_file (phase 2)

//on prend un fichier, on le chiffre, on le déchiffre,
//puis on verifie qu'on retrouve exactement le fichier de départ
// On vérifie aussi la taille du fichier chiffré et les cas d'erreur
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "rsa_file.h"
#include "int2char.h"
#include "io_utils.h"

static int echecs = 0;

//recoit la cond et compte les tests rates 
static void check(const char *nom, int condition) {
    printf("%s  %s\n", condition ? "OK   " : "ECHEC", nom);
    if (!condition) echecs++;
}

static void cas(const char *nom, const unsigned char *reste, size_t n, uint32_t attendu) {
    unsigned char bloc[4] = { 0, 0, 0, 0 };
    remplir_dernier_bloc(reste, n, bloc);
    check(nom, convert_4byte2int(bloc) == attendu);
}

// cle de test : N = 1000003*1000033 = 1000036000099 (plus grand que 2^32)
// PUB sert à chiffrer, PRIV à déchiffrer
static const rsaKey_t PUB      = { .N = 1000036000099ULL, .E = 65537ULL };
static const rsaKey_t PRIV     = { .N = 1000036000099ULL, .E = 983264276609ULL };
static const rsaKey_t MAUVAISE = { .N = 1000036000099ULL, .E = 983264276611ULL };

// Teste le chiffrement puis le dechiffrement du fichier

static void aller_retour(const char *nom, const uint8_t *data, size_t len, size_t taille_chiffre) {
    char msg[128];
    uint8_t *lu = NULL;
    size_t lu_len = 0; // taille de ce contenu
//creer le fich de depart

    write_file("tmp_clair.bin", data, len);
//on le chiffre 
    snprintf(msg, sizeof msg, "%s : chiffrement", nom);
    check(msg, chiffrer_fichier_bloc("tmp_clair.bin", "tmp_chiffre.bin", &PUB) == RSA_OK);
//on relit le fich chiffre et on controle sa taille 
    read_file("tmp_chiffre.bin", &lu, &lu_len);
    snprintf(msg, sizeof msg, "%s : %zu octets chiffres", nom, taille_chiffre);
    check(msg, lu_len == taille_chiffre);
    free(lu);
    lu = NULL;
//on le dechiffre 
    snprintf(msg, sizeof msg, "%s : dechiffrement", nom);
    check(msg, dechiffrer_fichier_bloc("tmp_chiffre.bin", "tmp_clair2.bin", &PRIV) == RSA_OK);
//le fichier obtenu doit être identique au départ
    read_file("tmp_clair2.bin", &lu, &lu_len);
    snprintf(msg, sizeof msg, "%s : contenu identique", nom);
    check(msg, lu_len == len && (len == 0 || memcmp(lu, data, len) == 0));
    free(lu);
}

int main(void) {
    const unsigned char un[1]    = { 0x6F };              // "o"
    const unsigned char deux[2]  = { 0x48, 0x69 };        // "Hi"
    const unsigned char trois[3] = { 0x61, 0x62, 0x63 };  // "abc"

    //les formes poss de bourage
   
    cas("0 octet  : 04 04 04 04", NULL,  0, 67372036);
    cas("1 octet  : 6F 03 03 03", un,    1, 50529135);
    cas("2 octets : 48 69 02 02", deux,  2, 33712456);
    cas("3 octets : 61 62 63 01", trois, 3, 23290465);

    // --- aller-retour ---
    const uint8_t hello[5] = { 'H', 'e', 'l', 'l', 'o' };
    const uint8_t huit[8]  = { 1, 2, 3, 4, 5, 6, 2, 2 };           // finit par 02 02 : vraies donnees
    const uint8_t utf8[6]  = { 'h', 0xC3, 0xA9, 'l', 'l', 'o' };   // "hello" avec e accent
    const uint8_t bin[8]   = { 0, 1, 2, 255, 254, 0, 255, 0 };
    //taille chiffree = (taille / 4 + 1) blocs * 8 octets
    aller_retour("Hello (5 octets)", hello, 5, 16);
    aller_retour("8 octets",         huit,  8, 24);
    aller_retour("fichier vide",     hello, 0, 8);
    aller_retour("UTF-8",            utf8,  6, 16);
    aller_retour("binaire avec 0",   bin,   8, 24);

    //cas d'erreurs
    //chiffre avec la bonne cle mais dechiffre avec la mauvaise
    write_file("tmp_clair.bin", hello, 5);
    chiffrer_fichier_bloc("tmp_clair.bin", "tmp_chiffre.bin", &PUB);
    check("mauvaise cle refusee",
          dechiffrer_fichier_bloc("tmp_chiffre.bin", "tmp_clair2.bin", &MAUVAISE) != RSA_OK);

    const uint8_t neuf[9] = { 1, 2, 3, 4, 5, 6, 7, 8, 9 };
    write_file("tmp_neuf.bin", neuf, 9);
    check("taille 9 (pas multiple de 8) refusee",
          dechiffrer_fichier_bloc("tmp_neuf.bin", "tmp_clair2.bin", &PRIV) == RSA_ERR_RANGE);
// fichier d'entree qui n'existe pas, et pointeur NULL en argument
    check("fichier inexistant",
          chiffrer_fichier_bloc("n_existe_pas.bin", "tmp_chiffre.bin", &PUB) == RSA_ERR_IO);
    check("pointeur NULL",
          chiffrer_fichier_bloc(NULL, "tmp_chiffre.bin", &PUB) == RSA_ERR_ARG);

    // supp les fichiers temporaires
    remove("tmp_clair.bin");
    remove("tmp_chiffre.bin");
    remove("tmp_clair2.bin");
    remove("tmp_neuf.bin");

    if (echecs == 0) printf("tous les tests passent\n");
    else printf("%d echec(s)\n", echecs);
    return echecs;
}