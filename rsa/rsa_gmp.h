#ifndef GMP_TOOLS_H
#define GMP_TOOLS_H

#include <gmp.h>
#include <stdint.h>
void puissance_mod_n_gmp(mpz_t res, uint64_t a, uint64_t e, uint64_t n);
#endif