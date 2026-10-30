#include "rsa_gmp.h"

// calcule res = a^e mod n
// mpz_powm reduit modulo n a chaque etape, donc les nombres restent petits
void puissance_mod_gmp(mpz_t res, const mpz_t a, const mpz_t e, const mpz_t n) {
    mpz_powm(res, a, e, n);
}