#ifndef CMD_CRYPTO_H
#define CMD_CRYPTO_H

#include "keyring.h"
#include "cmd_keys.h"   // pour CMD_OK et CMD_ERR_USAGE

int cmd_crypt(KeyRing *kr, int argc, char **argv);
int cmd_uncrypt(KeyRing *kr, int argc, char **argv);
int cmd_bin2b64(KeyRing *kr, int argc, char **argv);
int cmd_b642bin(KeyRing *kr, int argc, char **argv);
#endif