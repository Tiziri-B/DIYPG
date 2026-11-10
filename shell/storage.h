#ifndef STORAGE_H
#define STORAGE_H

#include "keyring.h"

// nom du fichier utilise quand l'utilisateur n'en donne pas
#define FICHIER_PAR_DEFAUT "diypg_keys.dat"

// Toutes les fonctions renvoient 0 si tout va bien, -1 sinon (+message d'erreur)

// save [<fichier>] 
int storage_save(const KeyRing *kr, const char *path);

// load [<fichier>] 
int storage_load(KeyRing *kr, const char *path);

// savepub <keyid> <fichier> 
int storage_savepub(KeyRing *kr, const char *keyid, const char *path);
