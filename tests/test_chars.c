#include <stdio.h>
#include "rsa_chars.h"

FILE *logfp = NULL; /*redefinition du header founris */

int main(void) {
    rsaKey_t pub  = { .E = 7,     .N = 97343 };
    rsaKey_t priv = { .E = 82903, .N = 97343 };
    int erreurs = 0;

    for (int m = 0; m < 256; m++) {
        uint64_t c;  /* resultat chifre sur 64*/
        uint8_t  r;  /* resultat chiffree sur 8 */

        if (chiffrer_char((uint8_t)m, &pub, &c) != RSA_OK
            || dechiffrer_char(c, &priv, &r) != RSA_OK
            || r != m) {
            printf("ECHEC pour m = %d\n", m);
            erreurs++;
        }
    }
    if (erreurs == 0) printf("OK : les 256 octets sont retrouves\n");
    else              printf("%d erreurs\n", erreurs);
    return erreurs != 0;
}
