#include "b64_file.h"

// lecture de tout un fichier en mémoire
// revoie un tableau d'octets (et on le libère avec free) et met sa taille dans *taille
// NULL si fichier ne peut pas etre lu
static unsigned char * lire_fichier(const char * chemin, size_t *taille) {
    FILE *f=fopen(chemin,"rb");
    if (f==NULL ) {
        fprintf(stderr, "  Erreur: impossible d'ouvrir %s \n",chemin);
        return NULL;
    }

    fseek(f,0,SEEK_END);
    long longueur=ftell(f);
    fseek(f,0,SEEK_SET);

    unsigned char *tab=malloc(longueur+1);
    if (tab==NULL) {
        fclose(f);
        return NULL;
    }

    if (fread(tab,1,longueur,f)!=(size_t)longueur) {
        fprintf(stderr,"Erreur : lecture incomplète de %s \n",chemin);
        free(tab);
        fclose(f);
        return NULL;
    }
    fclose(f);
    *taille=longueur;
    return tab;
}

// Vérifie qu'un texte est du base64 correct 
// longueur multiple de 4, que des caractères de l'alphabet base64, et des '=' seulement à la fin (2 au maximum).
// Renvoie 1 si c'est correct, 0 sinon.
static int base_valide(const char *texte, size_t n) {
    if (n%4!=0) return 0;

    size_t lettres = n;
    if (lettres>0 && texte[lettres-1]=='=') lettres--;
    if (lettres>0 && texte[lettres-1]=='=') lettres--;

    for (size_t i=0; i<lettres; i++) {
        char c=texte[i];
        int correct= (c>='A' && c<='Z') || (c>='a' && c<='z') || (c>='0' && c<='9') || c=='+' || c=='=' || c=='/';
        if (!correct) return 0;
    }
    return 1;
}

int fichier_vers_b64(const char *in, const char *out) {
    size_t taille=0;
    unsigned char *octets = lire_fichier (in,&taille);
    if (octets==NULL) return -1;

    size_t longueur =0;
    char *texte= base64_encode(octets,taille,&longueur);
    free(octets);
    if (texte==NULL) return -1 ;

    FILE *f = fopen(out,"wb");
    if (f==NULL) {
        fprintf (stderr," Erreur: impossible d'écrire dans %s \n",out);
        free(texte);
        return -1;
    }
    fwrite(texte,1,longueur,f);
    fputc('\n',f);
    free(texte);
    return 0;
}

int b64_vers_fichier(const char *in, const char *out) {
    size_t taille=0;
    unsigned char *fich = lire_fichier (in,&taille);
    if (fich==NULL) return -1;

    char *texte=(char*) fich;
    size_t n =0;
    for(size_t i=0; i<taille; i++) {
        if (fich[i]!='\n' && fich[i]!='\r' && fich[i]!=' ' && fich[i]!='\t') {
            texte[n]=fich[i];
            n++;
        }
    }

    if (!base_valide(texte,n)) {
        fprintf (stderr, " Erreur : %s ne contient pas du base64 valide \n ",in);
        return -1;
    }

    unsigned char *octets=NULL;
    size_t nb_octets=0;
    if (n>0) {
        octets = base64_decode(texte,n,&nb_octets);
        if (octets==NULL) {
            free(fich);
            return -1;
        }
    }
    free(fich);

    FILE *f=fopen(out,"wb");
    if (f==NULL ) {
        fprintf(stderr,"Erreur : impossible d'ecrire dans %s \n",out);
        free (octets);
        return -1 ;
    }
    if (nb_octets>0) {
        fwrite(octets,1,nb_octets,f);
    }
    fclose(f);
    free(octets);
    return 0;
}
