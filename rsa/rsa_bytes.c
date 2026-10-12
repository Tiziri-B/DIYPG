// chiffrement et dechiffrement de tableaux d octets et de fichiers
// un octet clair devient 8 octets chiffres

#include <stdlib.h>
#include "rsa_bytes.h"
#include "io_utils.h"
#include "rsa_chars.h"

// chiffre len octets avec la clef publique
// out est alloue ici et libere par l appelant
int chiffrer_octets(const uint8_t *in, size_t len, const rsaKey_t *pub, uint8_t **out, size_t *out_len) {
    // verif des pointeurs
    if (pub == NULL || out == NULL || out_len == NULL ||
        (len > 0 && in == NULL)) {
        return RSA_ERR_ARG;
    }

    // sorties a zero
    *out = NULL;
    *out_len = 0;

    // N doit tenir sur 32 bits sinon a*a deborde
    if (pub->N > UINT32_MAX) {
        return RSA_ERR_RANGE;
    }

    // debordement de 8 * len
    if (len > SIZE_MAX / 8) {
        return RSA_ERR_RANGE;
    }

    // 1 octet minimum pour ne pas avoir malloc(0)
    size_t taille = 8 * len;
    uint8_t *buffer = malloc(taille > 0 ? taille : 1);

    if (buffer == NULL) {
        return RSA_ERR_MEM;
    }

    // chaque octet est chiffre et range sur 8 octets
    for (size_t i = 0; i < len; i++) {
        uint64_t c;

        int err = chiffrer_char(in[i], pub, &c);

        if (err != RSA_OK) {
            free(buffer);
            return err;
        }

        put_u64_le(buffer + 8 * i, c);
    }

    // sorties remplies a la fin seulement
    *out = buffer;
    *out_len = taille;

    return RSA_OK;

}

// inverse de chiffrer_octets avec la clef privee
int dechiffrer_octets(const uint8_t *in, size_t len, const rsaKey_t *priv, uint8_t **out, size_t *out_len) {
    // verif des pointeurs
    if (priv == NULL || out == NULL || out_len == NULL || (len > 0 && in == NULL)) {
        return RSA_ERR_ARG;
    }

    // sorties a zero
    *out = NULL;
    *out_len = 0;

    // un chiffre fait 8 octets donc len multiple de 8
    if (len % 8 != 0) {
        return RSA_ERR_RANGE;
    }
    if (priv->N > UINT32_MAX) {
        return RSA_ERR_RANGE;
    }

    // 8 octets chiffres pour 1 octet clair
    size_t nb = len / 8;
    uint8_t *buffer = malloc(nb > 0 ? nb : 1);
    if (buffer == NULL) {
        return RSA_ERR_MEM;
    }

    // on relit chaque groupe de 8 octets et on dechiffre
    for (size_t i = 0; i < nb; i++) {
        uint64_t c = get_u64_le(in + 8 * i);
        uint8_t m;
        int err = dechiffrer_char(c, priv, &m);
        if (err != RSA_OK) {
            free(buffer);
            return err;
        }
        buffer[i] = m;
    }

    *out = buffer;
    *out_len = nb;
    return RSA_OK;
}

// lit in chiffre et ecrit le resultat dans out
int chiffrer_fichier(const char *in, const char *out, const rsaKey_t *pub) {
    if (in == NULL || out == NULL || pub == NULL) {
        return RSA_ERR_ARG;
    }

    // lecture
    uint8_t *clair = NULL;
    size_t clair_len = 0;
    if (read_file(in, &clair, &clair_len) != 0) {
        return RSA_ERR_IO;
    }

    // chiffrement
    uint8_t *chiffre = NULL;
    size_t chiffre_len = 0;
    int err = chiffrer_octets(clair, clair_len, pub, &chiffre, &chiffre_len);
    free(clair);
    if (err != RSA_OK) {
        return err;
    }

    // ecriture
    int res = write_file(out, chiffre, chiffre_len);
    free(chiffre);
    return (res == 0) ? RSA_OK : RSA_ERR_IO;
}

// meme chose dans l autre sens
int dechiffrer_fichier(const char *in, const char *out, const rsaKey_t *priv) {
    if (in == NULL || out == NULL || priv == NULL) {
        return RSA_ERR_ARG;
    }

    // lecture
    uint8_t *chiffre = NULL;
    size_t chiffre_len = 0;
    if (read_file(in, &chiffre, &chiffre_len) != 0) {
        return RSA_ERR_IO;
    }

    // dechiffrement
    uint8_t *clair = NULL;
    size_t clair_len = 0;
    int err = dechiffrer_octets(chiffre, chiffre_len, priv, &clair, &clair_len);
    free(chiffre);
    if (err != RSA_OK) {
        return err;
    }

    // ecriture
    int res = write_file(out, clair, clair_len);
    free(clair);
    return (res == 0) ? RSA_OK : RSA_ERR_IO;
}