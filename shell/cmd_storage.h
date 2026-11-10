#ifndef CMD_STORAGE_H
#define CMD_STORAGE_H

#include "keyring.h"
#include "cmd_keys.h" 

int cmd_save(KeyRing *kr, int argc, char **argv); 
int cmd_load(KeyRing *kr, int argc, char **argv);  
int cmd_savepub(KeyRing *kr, int argc, char **argv); 

#endif


