#include "rsa_gmp.h"

// calcule res = a^e mod n
// les uint64_t sont recopies dans des mpz_t car mpz_powm ne travaille que sur des mpz_t
// mpz_powm reduit modulo n a chaque etape, donc les nombres restent petits
void puissance_mod_n_gmp(mpz_t res, uint64_t a, uint64_t e, uint64_t n) {
    mpz_t A, E, N;
    mpz_init_set_ui(A, a);
    mpz_init_set_ui(E, e);
    mpz_init_set_ui(N, n);

    mpz_powm(res, A, E, N);

    // on libere les copies, res appartient a l'appelant
    mpz_clears(A, E, N, NULL);
}