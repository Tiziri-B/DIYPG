#include <stdio.h>
#include <stdint.h>  /* pour les entiers non signe sur 64 bit */

#include "rsa_common_header.h"


/*verifierque la cle publique /priv ne sont pas null 
et  verifier que le file ( path : chemain pour ariver au file)  existe*/
int key_save(const char *path, const rsaKey_t *pub, const rsaKey_t *priv) {
    if (path == NULL || pub == NULL || priv == NULL) {
        fprintf(stderr, "key_save : argument NULL\n");
        return -1;
    }

     /* ouverture fichier */
    FILE *fichier = fopen(path, "wb");
    if (fichier == NULL) {
        fprintf(stderr, "key_save : errur impossible d ouvrir le file \n");
        return -1;
    }

    /* Écriture  succesivement Epub  Npub   */
    if (fwrite(&(pub->E), sizeof(uint64_t), 1, fichier) != 1 ||
        fwrite(&(pub->N), sizeof(uint64_t), 1, fichier) != 1) {
        fprintf(stderr, "key_save : erreur ecriture cle publique\n");
        fclose(fichier);
        return -1;
    }

    /* Écriture  succesivement Epriv   Npriv  */
    if (fwrite(&(priv->E), sizeof(uint64_t), 1, fichier) != 1 ||
        fwrite(&(priv->N), sizeof(uint64_t), 1, fichier) != 1) {
        fprintf(stderr, "key_save : erreur ecriture cle privee\n");
        fclose(fichier);
        return -1;
    }
     /* fermeture du file */
    fclose(fichier);
    return 0;
}


/*verifierque la cle publique /priv ne sont pas null 
et  verifier que le file ( path : chemain pour ariver au file)  existe*/

int key_load(const char *path, rsaKey_t *pub, rsaKey_t *priv) {
    if (path == NULL || pub == NULL || priv == NULL) {
        fprintf(stderr, "key_load : argument NULL\n");
        return -1;
    }

    FILE *fichier = fopen(path, "rb");
    if (fichier == NULL) {
        fprintf(stderr, "key_load : fichier inexistant\n");
        return -1;
    }

    /* Lecture de Epub et N pub  */
    if (fread(&(pub->E), sizeof(uint64_t), 1, fichier) != 1 ||
        fread(&(pub->N), sizeof(uint64_t), 1, fichier) != 1) {
        fprintf(stderr, "key_load : erreur lecture clef publique\n");
        fclose(fichier);
        return -1;
    }

    /* Lecture de Epub et N pub  */
    if (fread(&(priv->E), sizeof(uint64_t), 1, fichier) != 1 ||
        fread(&(priv->N), sizeof(uint64_t), 1, fichier) != 1) {
        fprintf(stderr, "key_load : erreur lecture clef privee\n");
        fclose(fichier);
        return -1;
    }

    fclose(fichier);
    return 0; 
}