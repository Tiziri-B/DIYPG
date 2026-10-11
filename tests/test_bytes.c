// tests de la tache 3 : io_utils et rsa_bytes

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "io_utils.h"
#include "rsa_bytes.h"

// rsa_tools.c utilise logfp mais ne le definit pas
FILE *logfp = NULL;

static int echecs = 0;

static void check(const char *nom, int condition) {
    printf("%s  %s\n", condition ? "OK   " : "ECHEC", nom);
    if (!condition) echecs++;
}

// clefs de test
static const rsaKey_t PUB   = { .E = 3,    .N = 11413 };
static const rsaKey_t PRIV  = { .E = 7467, .N = 11413 };
static const rsaKey_t PUB2  = { .E = 17,   .N = 3233 };
static const rsaKey_t PRIV2 = { .E = 2753, .N = 3233 };

// compare deux fichiers octet par octet
static int memes_octets(const char *a, const char *b) {
    uint8_t *x = NULL, *y = NULL;
    size_t nx = 0, ny = 0;
    int ok = read_file(a, &x, &nx) == 0 && read_file(b, &y, &ny) == 0
             && nx == ny && (nx == 0 || memcmp(x, y, nx) == 0);
    free(x);
    free(y);
    return ok;
}

// ecrit build/<nom>_clair.bin puis chiffre et dechiffre
// les fichiers restent dans build pour le cmp
static void cas_fichier(const char *nom, const uint8_t *data, size_t len) {
    char clair[100], chiffre[100], retour[100], msg[160];
    snprintf(clair, sizeof clair, "build/%s_clair.bin", nom);
    snprintf(chiffre, sizeof chiffre, "build/%s_chiffre.bin", nom);
    snprintf(retour, sizeof retour, "build/%s_retour.bin", nom);

    write_file(clair, data, len);
    int r1 = chiffrer_fichier(clair, chiffre, &PUB);
    int r2 = dechiffrer_fichier(chiffre, retour, &PRIV);

    uint8_t *c = NULL;
    size_t cn = 0;
    read_file(chiffre, &c, &cn);
    free(c);

    snprintf(msg, sizeof msg, "fichier %s : chiffre 8 x taille et retour identique", nom);
    check(msg, r1 == RSA_OK && r2 == RSA_OK && cn == 8 * len && memes_octets(clair, retour));
}

// io_utils : ecriture
static void test_write(void) {
    const uint8_t hello[5] = { 0x48, 0x65, 0x6C, 0x6C, 0x6F };
    const uint8_t piege[4] = { 0x41, 0x0A, 0x1A, 0x42 };   // contient 0x0A et 0x1A

    printf("hello.bin : %d (attendu 0)\n",  write_file("build/hello.bin", hello, 5));
    printf("piege.bin : %d (attendu 0)\n",  write_file("build/piege.bin", piege, 4));
    printf("vide.bin  : %d (attendu 0)\n",  write_file("build/vide.bin", NULL, 0));
    printf("mauvais dossier : %d (attendu -1)\n", write_file("build/dossier_inexistant/x.bin", hello, 5));
}

// io_utils : lecture
static void test_read(void) {
    uint8_t *b = NULL;
    size_t n = 0;
    int r;

    const uint8_t hello[5] = { 0x48, 0x65, 0x6C, 0x6C, 0x6F };
    r = read_file("build/hello.bin", &b, &n);
    check("hello.bin : contenu", r == 0 && n == 5 && memcmp(b, hello, 5) == 0);
    free(b);

    // 0x0A et 0x1A ne doivent pas etre modifies (mode binaire)
    const uint8_t piege[4] = { 0x41, 0x0A, 0x1A, 0x42 };
    r = read_file("build/piege.bin", &b, &n);
    check("piege.bin : taille 4 et contenu", r == 0 && n == 4 && memcmp(b, piege, 4) == 0);
    free(b);

    r = read_file("build/vide.bin", &b, &n);
    check("vide.bin : taille 0", r == 0 && n == 0 && b != NULL);
    free(b);

    r = read_file("build/nexiste_pas.bin", &b, &n);
    check("fichier inexistant : -1, buf NULL et len 0", r == -1 && b == NULL && n == 0);
}

// chiffrer_octets : valeurs calculees a la main
static void test_chiffrer(void) {
    uint8_t *o = NULL;
    size_t n = 0;

    // 65^3 mod 11413 = 713 = 0x02C9 et 66^3 mod 11413 = 2171 = 0x087B
    const uint8_t m[2] = { 65, 66 };
    const uint8_t att[16] = { 0xC9,0x02,0,0,0,0,0,0, 0x7B,0x08,0,0,0,0,0,0 };
    int r = chiffrer_octets(m, 2, &PUB, &o, &n);
    check("chiffrer 65,66 avec (3,11413)", r == RSA_OK && n == 16 && memcmp(o, att, 16) == 0);
    free(o);
}

// dechiffrer_octets : un fichier chiffre fait un multiple de 8 octets
static void test_dechiffrer(void) {
    uint8_t *o = NULL;
    size_t n = 0;

    uint8_t c13[13] = {0};
    int r = dechiffrer_octets(c13, 13, &PRIV, &o, &n);
    check("longueur 13 : RSA_ERR_RANGE", r == RSA_ERR_RANGE && o == NULL && n == 0);
}

// les cas demandes pour les octets
static void test_octets(void) {
    uint8_t *ch = NULL, *cl = NULL;
    size_t chn = 0, cln = 0;
    int r1, r2;

    // tableau vide
    const uint8_t rien[1] = { 0 };
    r1 = chiffrer_octets(rien, 0, &PUB, &ch, &chn);
    r2 = dechiffrer_octets(ch, chn, &PRIV, &cl, &cln);
    check("tableau vide : aller-retour", r1 == RSA_OK && chn == 0 && r2 == RSA_OK && cln == 0);
    free(ch);
    free(cl);

    // 1 octet : les deux bords et une valeur au milieu
    const uint8_t valeurs[3] = { 0, 65, 255 };
    for (int k = 0; k < 3; k++) {
        char msg[80];
        r1 = chiffrer_octets(&valeurs[k], 1, &PUB, &ch, &chn);
        r2 = dechiffrer_octets(ch, chn, &PRIV, &cl, &cln);
        snprintf(msg, sizeof msg, "1 octet de valeur %d : aller-retour", valeurs[k]);
        check(msg, r1 == RSA_OK && chn == 8 && r2 == RSA_OK && cln == 1 && cl[0] == valeurs[k]);
        free(ch);
        free(cl);
    }

    // toutes les valeurs d un octet, avec les deux paires de clefs
    uint8_t tous[256];
    for (int k = 0; k < 256; k++) tous[k] = (uint8_t) k;
    r1 = chiffrer_octets(tous, 256, &PUB, &ch, &chn);
    r2 = dechiffrer_octets(ch, chn, &PRIV, &cl, &cln);
    check("256 valeurs avec N=11413", r1 == RSA_OK && r2 == RSA_OK && cln == 256 && memcmp(cl, tous, 256) == 0);
    free(ch);
    free(cl);

    r1 = chiffrer_octets(tous, 256, &PUB2, &ch, &chn);
    r2 = dechiffrer_octets(ch, chn, &PRIV2, &cl, &cln);
    check("256 valeurs avec N=3233", r1 == RSA_OK && r2 == RSA_OK && cln == 256 && memcmp(cl, tous, 256) == 0);
    free(ch);
    free(cl);

    // mauvaise clef : chiffre avec PUB et dechiffre avec PRIV2
    const uint8_t clair[1] = { 65 };
    chiffrer_octets(clair, 1, &PUB, &ch, &chn);
    r2 = dechiffrer_octets(ch, chn, &PRIV2, &cl, &cln);
    check("mauvaise clef : pas le message d'origine", r2 != RSA_OK || cl[0] != 65);
    free(cl);
    free(ch);
}

// les cas demandes pour les fichiers
static void test_fichiers(void) {
    // texte utf8 : Caf + e accent + espace + euro + espace + cadenas, ecrit en octets
    const uint8_t utf8[] = { 0x43,0x61,0x66, 0xC3,0xA9, 0x20, 0xE2,0x82,0xAC, 0x20, 0xF0,0x9F,0x94,0x92 };
    cas_fichier("utf8", utf8, sizeof utf8);

    // 0x00 0x1A 0x0A 0x0D sont les octets que le mode texte de windows abime
    const uint8_t binaire[8] = { 0x00, 0xFF, 0x1A, 0x0A, 0x0D, 0x00, 0x80, 0x41 };
    cas_fichier("binaire", binaire, 8);

    uint8_t tous[256];
    for (int k = 0; k < 256; k++) tous[k] = (uint8_t) k;
    cas_fichier("t256", tous, 256);

    cas_fichier("vide", NULL, 0);

    check("fichier introuvable : RSA_ERR_IO",
          chiffrer_fichier("build/introuvable.bin", "build/x.bin", &PUB) == RSA_ERR_IO);

    // mauvaise clef sur un fichier
    int r = dechiffrer_fichier("build/utf8_chiffre.bin", "build/utf8_mauvaise.bin", &PRIV2);
    check("fichier avec mauvaise clef : erreur ou contenu different",
          r != RSA_OK || !memes_octets("build/utf8_clair.bin", "build/utf8_mauvaise.bin"));
}

int main(void) {
    test_write();
    test_read();
    test_chiffrer();
    test_dechiffrer();
    test_octets();
    test_fichiers();

    if (echecs == 0) printf("tous les tests passent\n");
    else printf("%d echec(s)\n", echecs);
    return echecs;
}