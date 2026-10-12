# include <stdio.h>
# include <stdlib.h>

#include "../rsa/rsa_keys.h"

FILE *logfp;

int main(void) {
    keyPair_t paire;

    logfp=stderr

    generateKeys(&paire,max_prime);
    printKeyPair(paire);

    return 0;

}
