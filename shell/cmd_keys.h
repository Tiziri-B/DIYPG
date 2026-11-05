#ifndef CMD_KEYS_H
#define CMD_KEYS_H
#include "keyring.h"
#define CMD_OK 0
#define CMD_ERR_USAGE -10

int cmd_newkeys(KeyRing *kr , int argc ,char **argv);
int cmd_listkeys(KeyRing *kr , int argc ,char **argv);
int cmd_rmkeys(KeyRing *kr , int argc ,char **argv);
int cmd_show(KeyRing *kr , int argc ,char **argv);

#endif