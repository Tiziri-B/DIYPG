# include <stdio.h>
# include <stdlib.h>

#include "../rsa/rsa_keys.h"

FILE *logfp;

int main(void) {
    keyPair_t paire;

    logfp=stderr

    genererPaireCles(&paire,max_prime);
    afficherPaireCles(paire);

    return 0;

}
