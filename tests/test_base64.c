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

// convertir n octets en texte b64 puis inversement (texte=attendu?)
// reurn 1 si tout est bon, 0 sinon 
int aller_retour(const unsigned char *octets,size_t n,const char *attendu) {
    char *texte=NULL;
    unsigned char *retrouve=0;
    size_t nbRetrouve=0;
    int ok=1;
    if (b64_encode(octets,n,&texte)!=0) return 0;
    if (attendu!=NULL && strcmp(texte,attendu)!=0) ok=0;
    if (b64_decode(texte,&retrouve,&nbRetrouve)!=0 || nbRetrouve!=n || memcmp(retrouve,octets,n)!=0) ok=0;
    free(texte);
    free(retrouve);
    return ok;
}

// creer un fichier de taille au hasard
void creer_fichier(const char *chemin, int taille) {
    FILE *f=fopen(chemin,"wb");
    for (int i=0; i<taille; i++) {
        fputc(rand()%256,f);
    }
    fclose(f);
}

// return 1 si les fichiers ont le meme contenu , 0 sinon 
int meme_contenu(const char *chemin1,const char *chemin2) {
    FILE *f1=fopen(chemin1,"rb");
    FILE *f2=fopen(chemin2,"rb");

    if (f1 == NULL || f2 == NULL) {
        if (f1 != NULL) fclose(f1);
        if (f2 != NULL) fclose(f2);
        return 0;
    }

    int c1, c2;
    do {
        c1 = fgetc(f1);
        c2 = fgetc(f2);
    } while (c1 == c2 && c1 != EOF);

    fclose(f1);
    fclose(f2);
    return c1 == c2; 
}


int main(void) {
    srand(2026);

    // resultats echo -n 'Hi!'
    printf("\n***** Textes ***** \n");
    verifier(aller_retour((const unsigned char *) "Hi!",3,"SGkh"), "Hi! donne SGkh (exemple du sujet)");
    verifier(aller_retour((const unsigned char *) "Hi",2,"SGk="), "Hi donne SGk= ");
    verifier(aller_retour((const unsigned char *) "H",1,"SA=="), "H donne SA== ");
    verifier(aller_retour((const unsigned char *) "",0,""), "le texte vide donne un texte vide ");
    verifier(aller_retour((const unsigned char *) "un été",strlen("un été"),NULL), "texte avec des accents");

    // tableau d'octets
    printf("\n***** Tableau d'octets *****\n");
    unsigned char tous[256];
    for (int i=0; i<256; i++) {
        tous[i]=i;
    }
    verifier(aller_retour(tous,256,NULL), "les 256 valeurs d'octets");

    // entiers 
    printf("\n***** Entiers uint32 *****\n");
    uint32_t a=1;
    verifier(aller_retour((const unsigned char *)&a,sizeof(a),"AQAAAA=="),"uint32 : 1 donne AQAAAA==");
    a = 4294967295u;
    verifier(aller_retour((const unsigned char *) &a, sizeof a, "/////w=="), "uint32 : 4294967295 donne /////w==");
    a = 123456789;
    verifier(aller_retour((const unsigned char *) &a, sizeof a, NULL), "uint32 : 123456789 aller-retour");

    printf("\n***** Entiers uint64 *****\n");
    uint64_t b = 1;
    verifier(aller_retour((const unsigned char *) &b, sizeof b, "AQAAAAAAAAA="), "uint64 : 1 donne AQAAAAAAAAA=");
     b = 0x0123456789ABCDEFULL;
    verifier(aller_retour((const unsigned char *) &b, sizeof b, NULL), "uint64 : 0x0123456789ABCDEF aller-retour");


    // les clés
    printf("\n***** CLé RSA *****\n");
    rsaKey_t cle;
    cle.E=3;
    cle.N=33;
    verifier(aller_retour((const unsigned char *) &cle, sizeof cle, "AwAAAAAAAAAhAAAAAAAAAA=="),"clef (E = 3, N = 33) donne AwAAAAAAAAAhAAAAAAAAAA==");

    // textes base64 incorrectes --> refusés 
    printf("\n***** Textes base64 incorrectes *****\n");
    unsigned char *octets =NULL;
    size_t nb=0;
    verifier(b64_decode("abc", &octets, &nb) == -1, "« abc » refusé (3 caractères : pas un multiple de 4)");
    verifier(b64_decode("ab!d", &octets, &nb) == -1, "« ab!d » refusé (le caractère ! n'existe pas en base64)");
    verifier(b64_decode("ab=c", &octets, &nb) == -1, "« ab=c » refusé (un = au milieu)");

    // fichiers
    printf("\n***** Fichiers *****\n");
    const char *source = "build/tmp_b64_source.bin";
    const char *texte = "build/tmp_b64_texte.txt";
    const char *retour = "build/tmp_b64_retour.bin";
    int tailles[] = {0, 1, 2, 3, 100, 1000};
    char message[100];

    for (int i = 0; i < 6; i++) {
        creer_fichier(source, tailles[i]);
        int ok = (fichier_vers_b64(source, texte) == 0)         // fichier -> texte base64
              && (b64_vers_fichier(texte, retour) == 0)         // texte base64 -> fichier
              && meme_contenu(source, retour);                  // même contenu qu'au départ ?
        snprintf(message, sizeof message, "fichier de %d octets : aller-retour", tailles[i]);
        verifier(ok, message);
    } 

    //  fichier base64 sur plusieurs lignes
    FILE *f = fopen(texte, "wb");
    fputs("SGkh\nSGkh\n", f);
    fclose(f);
    f = fopen(source, "wb");
    fputs("Hi!Hi!", f);
    fclose(f);
    verifier(b64_vers_fichier(texte, retour) == 0 && meme_contenu(source, retour),"fichier base64 sur 2 lignes décodé en Hi!Hi!");

    verifier(fichier_vers_b64("build/fichier_qui_n_existe_pas", texte) == -1, "fichier absent : erreur");
    f = fopen(source, "wb");
    fputs("abc!", f);                       // ce texte n'est pas du base64
    fclose(f);
    verifier(b64_vers_fichier(source, retour) == -1, "fichier base64 invalide : erreur");

     // On supprime les fichiers de test
    remove(source);
    remove(texte);
    remove(retour);
    base64_cleanup();   

    printf("\n");
    if (nbEchecs==0) printf ("Tout est OK \n");
    else printf ("%d vérification(s) ratée(s) \n",nbEchecs);
    return nbEchecs;
}