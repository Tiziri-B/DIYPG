# include <stdio.h>
# include <inttypes.h> // afficher et manipuler types uint64_t
# include "rsa_keys.h"
# include "rsa_tools.h" 


FILE *logfp = NULL;

void keys_set_log(FILE *f){
    logfp= f;
}

void printKey(const rsaKey_t *k, FILE *out) {
    if (k== NULL || out == NULL) return;
    fprintf(out,"E = 0x%" PRIx64 "\n",k->E);
    fprintf(out,"N = 0x%" PRIx64 "\n", k->N);
    // PRIx64 : permet d’afficher un entier non signé de 64 bits en hexa
}

void printKeyPair(const rsaKey_t *pub, const rsaKey_t *priv, FILE *out){
    fprintf(out,"***** Clé publique *****\n");
    printKey(pub,out);

    fprintf(out,"\n***** Clé privée *****\n");
    printKey(priv,out);
    fprintf(out,"\n");
}


int keyCheck (const rsaKey_t *pub, const rsaKey_t *priv){
    if (pub==NULL || priv==NULL) return 0;
    if (pub->N!=priv->N || pub->N <= 255) return 0;

    for (uint64_t m=0; m<256; m++) {
        uint64_t c=puissance_mod_n(m,pub->E,pub->N); //chiffrement
        if (puissance_mod_n(c,priv->E,priv->N)!=m) return 0; // dechiffrement
    }
    return 1;
}



int generateKeys(rsaKey_t *pub, rsaKey_t *priv) {
    if (pub==NULL || priv==NULL) return -1;
    if (logfp==NULL) logfp=tmpfile(); // necessaire pour genKeysRabin
    if (logfp==NULL) return -1;

    for (int essai=0 ; essai < KEYS_TRIES; essai++) {
        genKeysRabin(pub,priv,MAX_PRIME);
        if (keyCheck(pub,priv)) return 0;
    }

    return -1;
}


// Meme fonction que puissance_mod_n mais avec 128 bits
static uint64_t puissance_mod_128 (uint64_t a, uint64_t e, uint64_t n) {
  unsigned __int128 p=1;
  unsigned __int128 base=a%n;
  for (p = 1; e > 0; e = e / 2) {
    if (e % 2 != 0)
      p = (p * base) % n;
    base = (base * base) % n;
  }
  return (uint64_t)p;
}

// Donner un nombre premier entre (2^16+1) et environ (2^31)
// meme fonction que genereUintRabin mais on recommence si nombre est trop petit
static uint64_t premier_blocs(void) {
  uint64_t num;
  int cpt;
  do{
    num = genereUintRabin(1ULL<<31,&cpt);
  } while (num<=(1ULL<<16));
  return num;
}

int keyCheckBlock(const rsaKey_t *pub, const rsaKey_t *priv) {
    if (pub==NULL || priv==NULL) return 0;
    if (pub->N!=priv->N ) return 0;
    if (pub->N <= ((1ULL<<32)-1)) return 0;

    uint64_t tests[8] = {0,1,2,255,1ULL<<16,123456789,(1ULL<<32)-2,(1ULL<<32)-1};
    for (int i=0; i<8; i++) {
        uint64_t c=puissance_mod_128(tests[i],pub->E,pub->N); //chiffrement
        if (puissance_mod_128(c,priv->E,priv->N)!=tests[i]) return 0; // dechiffrement
    }
    return 1;
}

int generateKeysBlock(rsaKey_t *pub, rsaKey_t *priv) {
    if (pub==NULL || priv==NULL) return -1;
    if (logfp==NULL) logfp=tmpfile(); 
    if (logfp==NULL) return -1;

    for (int essai=0 ; essai < KEYS_TRIES; essai++) {
        uint64_t num1 = premier_blocs();
        uint64_t num2 = premier_blocs();

        while (num2 == num1)
        num2 = premier_blocs();

        uint64_t N = num1*num2;
        uint64_t M = (num1-1)*(num2-1); 

        uint64_t C = (1ULL<<16)+1;
        while (pgcdFast(C,M)!=1 && C<M){
            C=C+2;
        }

        int64_t U,V;
        bezoutRSA(C,M,&U,&V);

        pub->E = C;
        pub->N = N;
        priv->E = U;
        priv->N = N;
        if (keyCheckBlock(pub,priv)) return 0;
    }

    return -1;
}

