# include <stdio.h> 
# include <string.h>

# include "../codec/b64_file.h"
#include "../rsa/rsa_common_header.h" 

int nbEchecs =0;

void verifier (int c , const char * msg) {
    if (c) printf("OK : %s\n", msg);
    else {
        printf("ECHEC : %s\n", msg);
        nbEchecs++;
    }
}

