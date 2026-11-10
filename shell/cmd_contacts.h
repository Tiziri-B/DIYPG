#ifndef CMD_CONTACTS_H
#define CMD_CONTACTS_H

#include "keyring.h"
#include "cmd_keys.h"  

int cmd_listcontacts(KeyRing *kr, int argc, char **argv);
int cmd_addcontact(KeyRing *kr, int argc, char **argv);
int cmd_modifycontact(KeyRing *kr, int argc, char **argv);
int cmd_addkeys(KeyRing *kr, int argc, char **argv);
int cmd_rmcontact(KeyRing *kr, int argc, char **argv);

#endif