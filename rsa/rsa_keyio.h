#ifndef RSA_KEYIO_H
#define RSA_KEYIO_H

#include <stdio.h>
#include <stdint.h>
#include "rsa_common_header.h"

int key_save(const char *path, const rsaKey_t *pub, const rsaKey_t *priv);
int key_load(const char *path, rsaKey_t *pub, rsaKey_t *priv);

#endif
