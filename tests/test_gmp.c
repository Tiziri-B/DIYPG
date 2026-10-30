// tests de puissance_mod_n_gmp (phase 2)

#include <stdio.h>
#include <gmp.h>
#include "rsa_gmp.h"

static int echecs = 0;

static void check(const char *nom, int condition) {
    printf("%s  %s\n", condition ? "OK   " : "ECHEC", nom);
    if (!condition) echecs++;
}

// calcule a^e mod n et compare avec le resultat attendu (donne en decimal)
static void cas(const char *nom, uint64_t a, uint64_t e, uint64_t n, const char *attendu) {
    mpz_t R, ATT;
    mpz_inits(R, ATT, NULL);
    mpz_set_str(ATT, attendu, 10);

    puissance_mod_n_gmp(R, a, e, n);

    check(nom, mpz_cmp(R, ATT) == 0);
    if (mpz_cmp(R, ATT) != 0) gmp_printf("   obtenu %Zd attendu %Zd\n", R, ATT);

    mpz_clears(R, ATT, NULL);
}

int main(void) {
    // valeurs de la phase 1
    cas("65^3 mod 11413 = 713",    65,   3,    11413, "713");
    cas("713^7467 mod 11413 = 65", 713,  7467, 11413, "65");
    cas("65^17 mod 3233 = 2790",   65,   17,   3233,  "2790");
    cas("2790^2753 mod 3233 = 65", 2790, 2753, 3233,  "65");

    // cas limites
    cas("exposant 0 donne 1", 123, 0,  11413, "1");
    cas("base 0 donne 0",     0,   5,  11413, "0");
    cas("modulo 1 donne 0",   123, 45, 1,     "0");

    // N plus grand que 2^32 (4294967311 est premier) : la phase 1 ne savait pas le faire
    cas("4000000000^65537 mod 4294967311", 4000000000ULL, 65537, 4294967311ULL, "2902631179");

    // petit theoreme de Fermat : p premier donc a^(p-1) mod p = 1
    cas("Fermat avec p = 4294967311", 123456789, 4294967310ULL, 4294967311ULL, "1");

    if (echecs == 0) printf("tous les tests passent\n");
    else printf("%d echec(s)\n", echecs);
    return echecs;
}