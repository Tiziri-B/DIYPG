#ifndef CONTACTS_H
#define CONTACTS_H

#include "keyring.h"  


int contact_add(KeyRing *kr, const char *id, const char *nom, const char *prenom, const char *commentaire);
int contact_modify(KeyRing *kr, const char *id, const char *nom, const char *prenom, const char *commentaire);
int contact_remove(KeyRing *kr, const char *id);
int contact_addkey(KeyRing *kr, const char *id_contact, const char *id_clef, const char *type, const rsaKey_t *pub);
int contact_removekey(KeyRing *kr, const char *id_contact, const char *id_clef);
Contact *contact_find(KeyRing *kr, const char *id);
Contact *contact_find_name(KeyRing *kr, const char *nom);
ContactKey *contact_findkey(KeyRing *kr, const char *ref);   
void contact_list(const KeyRing *kr, const char *id_ou_nom);

#endif
