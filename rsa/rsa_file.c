#include "rsa_file.h"
#include <stdlib.h>
#include "io_utils.h"
#include "int2char.h"
void remplir_dernier_bloc(const unsigned char *reste, size_t n, unsigned char bloc[4])
{
    unsigned char pad = 4 - n;
    for (size_t i = 0; i < 4; i++) {
        if (i < n) {
            bloc[i] = reste[i];   // l'octet du fichier
        } else {
            bloc[i] = pad;   // le bourrage
        }
    }
}
int chiffrer_fichier_bloc(const char *in, const char *out, const rsaKey_t *pub) {
    if (in == NULL || out == NULL || pub == NULL) {
        return RSA_ERR_ARG;
    }

    // lecture du fichier 
    uint8_t *clair = NULL;
    size_t clair_len = 0;
    if (read_file(in, &clair, &clair_len) != 0) {//en cas d'erreur
        return RSA_ERR_IO;
    }

    size_t nb_complets = clair_len / 4;     
    size_t reste_n     = clair_len % 4;     
    size_t nb_blocs    = nb_complets + 1;   

    uint8_t *chiffre = malloc(nb_blocs * 8);
      //reserver les octets
    if (chiffre == NULL) {
        free(clair);
        return RSA_ERR_MEM;
    }

    //blocs complets
    for (size_t i = 0; i < nb_complets; i++) {
        uint32_t m = convert_4byte2int(clair + 4 * i);
        uint64_t c;
        //chiffrer chaque bloc
        int err = chiffrer_bloc(m, pub, &c);
        if (err != RSA_OK) {
            free(clair);
            free(chiffre);
            return err;
        }
        put_u64_le(chiffre + 8 * i, c);
    }

// On complète le dernier bloc pour avoir 4 octets
    uint8_t bloc[4];
    remplir_dernier_bloc(clair + 4 * nb_complets, reste_n, bloc);
    uint32_t m = convert_4byte2int(bloc);
    uint64_t c;
    int err = chiffrer_bloc(m, pub, &c);
    free(clair);
    if (err != RSA_OK) {
        free(chiffre);
        return err;
    }
    put_u64_le(chiffre + 8 * nb_complets, c);

    // ecriture
    int res = write_file(out, chiffre, nb_blocs * 8);
    free(chiffre);
    return (res == 0) ? RSA_OK : RSA_ERR_IO;
}


//dechiffrer fich 
int dechiffrer_fichier_bloc(const char *in, const char *out, const rsaKey_t *priv)
{
    if (in == NULL || out == NULL || priv == NULL) {
        return RSA_ERR_ARG;
    }
    //lecture
    uint8_t *chiffre = NULL;
    size_t chiffre_len = 0;
    if (read_file(in, &chiffre, &chiffre_len) != 0) {
        return RSA_ERR_IO;
    }
    // au moins 1 bloc, et un nombre entier de blocs de 8 octets
    if (chiffre_len < 8 || chiffre_len % 8 != 0) {
        free(chiffre);
        return RSA_ERR_RANGE;
    }
    size_t nb_blocs  = chiffre_len / 8;
    size_t clair_len = nb_blocs * 4; 
     uint8_t *clair = malloc(clair_len);
    if (clair == NULL) {
        free(chiffre);
        return RSA_ERR_MEM;
    }

    // dechiffrer chaque bloc
    for (size_t i = 0; i < nb_blocs; i++) {
        uint64_t c = get_u64_le(chiffre + 8 * i);
        uint32_t m;
        int err = dechiffrer_bloc(c, priv, &m);
        if (err != RSA_OK) {
            free(chiffre);
            free(clair);
            return err;
        }
        convertInt2uchar(m, clair + 4 * i);
    }
    free(chiffre);   // plus besoin du chiffre

    // retirer le bourrage : le dernier octet donne k
    uint8_t k = clair[clair_len - 1];
    if (k < 1 || k > 4) {
        free(clair);
        return RSA_ERR_RANGE;
    }
    // les k derniers octets doivent tous valoir k
    for (size_t j = 0; j < k; j++) {
        if (clair[clair_len - 1 - j] != k) {
            free(clair);
            return RSA_ERR_RANGE;
        }
    }

    // ecriture sans le bourrage
    int res = write_file(out, clair, clair_len - k);
    free(clair);
    return (res == 0) ? RSA_OK : RSA_ERR_IO;

}