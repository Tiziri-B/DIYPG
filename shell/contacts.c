#include <stdio.h>
#include <string.h>
#include "contacts.h"

static int identifiant_ok(const char *id) {
    if (id == NULL) return 0;
    size_t longueur = strlen(id);
    if (longueur == 0 || longueur >= NAME_MAX_SIZE) return 0;
    for (size_t i = 0; i < longueur; i++) {
        if (id[i] == ' ' || id[i] == '\t' || id[i] == '/' || id[i] == '\n' || id[i] == '\r' ||id[i] == '|' ) return 0;
    }
    return 1;
}

static int texte_ok(const char *texte) {
    return texte != NULL && strlen(texte) < TEXTE_MAX && strpbrk(texte, "\r\n|") == NULL;
}

Contact *contact_find(KeyRing *kr, const char *id) {
    if (kr == NULL || id == NULL) return NULL;
    for (int i = 0; i < kr->nb_contacts; i++) {
        if (strcmp(kr->contacts[i].id, id) == 0) return &kr->contacts[i];
    }
    return NULL;
}

Contact *contact_find_name(KeyRing *kr, const char *nom) {
    if (kr == NULL || nom == NULL) return NULL;
    for (int i = 0; i < kr->nb_contacts; i++)
        if (strcmp(kr->contacts[i].nom, nom) == 0) return &kr->contacts[i];
    return NULL;
}

// cherche une clef de contact a partir de "idcontact/idclef"
ContactKey *contact_findkey(KeyRing *kr, const char *ref) {
    if (kr == NULL || ref == NULL) return NULL;
    const char *slash = strchr(ref, '/');
    if (slash == NULL || slash - ref >= NAME_MAX_SIZE) return NULL;

    char id_contact[NAME_MAX_SIZE];
    memcpy(id_contact, ref, slash - ref);
    id_contact[slash - ref] = '\0';

    Contact *c = contact_find(kr, id_contact);
    if (c == NULL) return NULL;
    for (int i = 0; i < c->nb_cles; i++)
        if (strcmp(c->cles[i].id, slash + 1) == 0) return &c->cles[i];
    return NULL;
}


int contact_add(KeyRing *kr, const char *id, const char *nom, const char *prenom, const char *commentaire) {
    if (kr == NULL) return KR_ERR_PTR;
    if (!identifiant_ok(id)) return KR_ERR_BADID;
    if (!texte_ok(nom) || !texte_ok(prenom) || !texte_ok(commentaire)) return KR_ERR_BADTEXT;
    if (contact_find(kr, id) != NULL) return KR_ERR_EXISTS;
    if (kr->nb_contacts >= MAX_CONTACTS) return KR_ERR_FULL;

    
    Contact *c = &kr->contacts[kr->nb_contacts];
    strcpy(c->id, id);
    strcpy(c->nom, nom);
    strcpy(c->prenom, prenom);
    strcpy(c->commentaire, commentaire);
    c->nb_cles = 0;
    kr->nb_contacts++;
    return KR_OK;
}

int contact_modify(KeyRing *kr, const char *id, const char *nom, const char *prenom, const char *commentaire) {
    if (kr == NULL) return KR_ERR_PTR;
    Contact *c = contact_find(kr, id);
    if (c == NULL) return KR_ERR_NOTFOUND;
    if (!texte_ok(nom) || !texte_ok(prenom) || !texte_ok(commentaire)) return KR_ERR_BADTEXT;
    strcpy(c->nom, nom); strcpy(c->prenom, prenom); strcpy(c->commentaire, commentaire);
    return KR_OK;
}

int contact_remove(KeyRing *kr, const char *id) {
    if (kr == NULL || id == NULL) return KR_ERR_PTR;
    int i;
    for (i = 0; i < kr->nb_contacts; i++) if (strcmp(kr->contacts[i].id, id) == 0) break;
    if (i == kr->nb_contacts) return KR_ERR_NOTFOUND;
    for (; i < kr->nb_contacts - 1; i++) kr->contacts[i] = kr->contacts[i + 1];
    kr->nb_contacts--;
    memset(&kr->contacts[kr->nb_contacts], 0, sizeof(Contact));
    return KR_OK;
}

int contact_addkey(KeyRing *kr, const char *id_contact, const char *id_clef, const char *type, const rsaKey_t *pub) {
    if (kr == NULL || pub == NULL) return KR_ERR_PTR;
    Contact *c = contact_find(kr, id_contact);
    if (c == NULL) return KR_ERR_NOTFOUND;
    if (!identifiant_ok(id_clef)) return KR_ERR_BADID;
    if (type == NULL || (strcmp(type, KEY_TYPE_CRYPT) != 0 && strcmp(type, KEY_TYPE_SIGN) != 0)) return KR_ERR_TYPAGE;
    for (int i = 0; i < c->nb_cles; i++) {
        if (strcmp(c->cles[i].id, id_clef) == 0) return KR_ERR_EXISTS;
    }
    if (c->nb_cles >= MAX_CLES_CONTACT) return KR_ERR_FULL;

    ContactKey *k = &c->cles[c->nb_cles];
    strcpy(k->id, id_clef);
    strcpy(k->type, type);
    k->pubKey = *pub;
    c->nb_cles++;
    return KR_OK;
}

int contact_removekey(KeyRing *kr, const char *id_contact, const char *id_clef) {
    if (kr == NULL || id_clef == NULL) return KR_ERR_PTR;
    Contact *c = contact_find(kr, id_contact);
    if (c == NULL) return KR_ERR_NOTFOUND;
    int i;
    for (i = 0; i < c->nb_cles; i++) if (strcmp(c->cles[i].id, id_clef) == 0) break;
    if (i == c->nb_cles) return KR_ERR_NOTFOUND;
    for (; i < c->nb_cles - 1; i++) c->cles[i] = c->cles[i + 1];
    c->nb_cles--;
    memset(&c->cles[c->nb_cles], 0, sizeof(ContactKey));
    return KR_OK;
}

void contact_list(const KeyRing *kr, const char *id_ou_nom) {
    if (kr == NULL) return;
    int trouve = 0;
    for (int i = 0; i < kr->nb_contacts; i++) {
        const Contact *c = &kr->contacts[i];
        if (id_ou_nom != NULL && strcmp(c->id, id_ou_nom) != 0 && strcmp(c->nom, id_ou_nom) != 0) continue;
        trouve = 1;
        printf("Identifiant : %s\nNom : %s\nPrenom : %s\nCommentaire : %s\n", c->id, c->nom, c->prenom, c->commentaire);
        printf("Cles (%d) :\n", c->nb_cles);
        for (int j = 0; j < c->nb_cles; j++) printf("  - %s : %s\n", c->cles[j].id, c->cles[j].type);
    }
    if (!trouve) printf("Aucun contact trouve.\n");
}