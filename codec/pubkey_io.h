#ifndef PUBKEY_IO_H
#define PUBKEY_IO_H

#include "rsa_common_header.h"

// ecrit la clé dans un fichier en base 64
// 0 si ok, -1 sinon
int pubkey_export(const char *path,const rsaKey_t *pub) ;

// lit un fichier (ecrit pas pubkey_export) et remplit *pub
// 0 si ok (+ *pub est modifie) , -1 sinon 
int pubkey_import(const char *path, rsaKey_t *pub);

#endif