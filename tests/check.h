#ifndef CHECK_H
#define CHECK_H

#include <stdio.h>

static int nbEchecs = 0;

static void verifier(const char * msg,int cnd) {
    if (cnd) printf ("OK : %s\n",msg);
    else {
        printf("ECHEC : %s\n",msg);
        nbEchecs++;
    }
}

#endif