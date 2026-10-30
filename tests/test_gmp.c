// tests de puissance_mod_gmp (phase 2)

#include <stdio.h>
#include <gmp.h>
#include "rsa_gmp.h"

static int echecs = 0;

static void check(const char *nom, int condition) {
    printf("%s  %s\n", condition ? "OK   " : "ECHEC", nom);
    if (!condition) echecs++;
}

// calcule a^e mod n (nombres donnes en decimal) et compare avec le resultat attendu
static void cas(const char *nom, const char *a, const char *e, const char *n, const char *attendu) {
    mpz_t A, E, N, R, ATT;
    mpz_inits(A, E, N, R, ATT, NULL);
    mpz_set_str(A, a, 10);
    mpz_set_str(E, e, 10);
    mpz_set_str(N, n, 10);
    mpz_set_str(ATT, attendu, 10);

    puissance_mod_gmp(R, A, E, N);

    check(nom, mpz_cmp(R, ATT) == 0);
    if (mpz_cmp(R, ATT) != 0) gmp_printf("   obtenu %Zd attendu %Zd\n", R, ATT);

    mpz_clears(A, E, N, R, ATT, NULL);
}

int main(void) {
    // petites valeurs deja utilisees en phase 1
    cas("65^3 mod 11413 = 713",    "65",   "3",    "11413", "713");
    cas("713^7467 mod 11413 = 65", "713",  "7467", "11413", "65");
    cas("65^17 mod 3233 = 2790",   "65",   "17",   "3233",  "2790");
    cas("2790^2753 mod 3233 = 65", "2790", "2753", "3233",  "65");

    // cas limites
    cas("exposant 0 donne 1", "123", "0",  "11413", "1");
    cas("base 0 donne 0",     "0",   "5",  "11413", "0");
    cas("modulo 1 donne 0",   "123", "45", "1",     "0");

    // plus grand que 64 bits : 2^100 mod (2^89 - 1) = 2^11 = 2048
    cas("2^100 mod (2^89-1) = 2048", "2", "100", "618970019642690137449562111", "2048");

    // p = 2^127 - 1 est premier, donc a^(p-1) mod p = 1 (petit theoreme de Fermat)
    cas("Fermat avec p = 2^127-1", "123456789",
        "170141183460469231731687303715884105726",
        "170141183460469231731687303715884105727", "1");

    if (echecs == 0) printf("tous les tests passent\n");
    else printf("%d echec(s)\n", echecs);
    return echecs;
}