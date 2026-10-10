#include <stdio.h>
#include "io_utils.h"
#include <stdlib.h>
#include <string.h>
static int echecs = 0;

static void verifier(uint64_t v) {
    uint8_t octets[8];
    put_u64_le(octets, v);

    uint64_t relu = get_u64_le(octets);

    printf("%llu ->", (unsigned long long) v);
    for (int k = 0; k < 8; k++) {
        printf(" %02X", octets[k]);
    }
    printf(" -> relu %llu : %s\n", (unsigned long long) relu, relu == v ? "OK" : "ECHEC");

    if (relu != v) echecs++;
}
static void check(const char *nom, int condition) {
    printf("%s  %s\n", condition ? "OK   " : "ECHEC", nom);
    if (!condition) echecs++;
}

static void test_read(void) {
    uint8_t *b = NULL;
    size_t n = 0;
    int r;

    const uint8_t hello[5] = { 0x48, 0x65, 0x6C, 0x6C, 0x6F };
    r = read_file("build/hello.bin", &b, &n);
    check("hello.bin : retour 0", r == 0);
    check("hello.bin : taille 5", n == 5);
    check("hello.bin : contenu", b != NULL && n == 5 && memcmp(b, hello, 5) == 0);
    free(b);

    const uint8_t piege[4] = { 0x41, 0x0A, 0x1A, 0x42 };
    r = read_file("build/piege.bin", &b, &n);
    check("piege.bin : taille 4 (mode binaire)", r == 0 && n == 4);
    check("piege.bin : contenu", b != NULL && n == 4 && memcmp(b, piege, 4) == 0);
    free(b);

    r = read_file("build/vide.bin", &b, &n);
    check("vide.bin : retour 0, taille 0, buffer non NULL", r == 0 && n == 0 && b != NULL);
    free(b);

    uint8_t dummy;
    b = &dummy;
    n = 99;
    r = read_file("build/nexiste_pas.bin", &b, &n);
    check("fichier inexistant : retour -1", r == -1);
    check("fichier inexistant : buf NULL et len 0", b == NULL && n == 0);

    r = read_file(NULL, &b, &n);
    check("path NULL : retour -1", r == -1);

    uint8_t tous[256];
    for (int k = 0; k < 256; k++) tous[k] = (uint8_t) k;
    write_file("build/t256.bin", tous, 256);
    r = read_file("build/t256.bin", &b, &n);
    check("aller-retour des 256 octets", r == 0 && n == 256 && b != NULL && memcmp(b, tous, 256) == 0);
    free(b);
}
static void test_write(void) {
    const uint8_t hello[5] = { 0x48, 0x65, 0x6C, 0x6C, 0x6F };   // "Hello"
    const uint8_t piege[4] = { 0x41, 0x0A, 0x1A, 0x42 };         // contient 0x0A et 0x1A

    printf("hello.bin : %d (attendu 0)\n",  write_file("build/hello.bin", hello, 5));
    printf("piege.bin : %d (attendu 0)\n",  write_file("build/piege.bin", piege, 4));
    printf("vide.bin  : %d (attendu 0)\n",  write_file("build/vide.bin", NULL, 0));
    printf("mauvais dossier : %d (attendu -1)\n", write_file("build/dossier_inexistant/x.bin", hello, 5));
    printf("path NULL : %d (attendu -1)\n", write_file(NULL, hello, 5));
}

int main(void) {
   test_write();
   test_read();
}