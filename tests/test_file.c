// tests de rsa_file (phase 2)

#include <stdio.h>
#include "rsa_file.h"
#include "int2char.h"

static int echecs = 0;

static void check(const char *nom, int condition) {
    printf("%s  %s\n", condition ? "OK   " : "ECHEC", nom);
    if (!condition) echecs++;
}

// fabrique le dernier bloc et compare sa valeur (en entier) avec l'attendu
static void cas(const char *nom, const unsigned char *reste, size_t n, uint32_t attendu) {
    unsigned char bloc[4] = { 0, 0, 0, 0 };
    remplir_dernier_bloc(reste, n, bloc);
    check(nom, convert_4byte2int(bloc) == attendu);
}

int main(void) {
    const unsigned char un[1]    = { 0x6F };              // "o"
    const unsigned char deux[2]  = { 0x48, 0x69 };        // "Hi"
    const unsigned char trois[3] = { 0x61, 0x62, 0x63 };  // "abc"

    // avec 0 octet restant, reste n'est pas lu : on peut passer NULL
    cas("0 octet  : 04 04 04 04", NULL,  0, 67372036);
    cas("1 octet  : 6F 03 03 03", un,    1, 50529135);
    cas("2 octets : 48 69 02 02", deux,  2, 33712456);
    cas("3 octets : 61 62 63 01", trois, 3, 23290465);

    if (echecs == 0) printf("tous les tests passent\n");
    else printf("%d echec(s)\n", echecs);
    return echecs;
}