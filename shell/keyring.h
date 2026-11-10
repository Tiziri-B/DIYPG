#ifndef KEYRING_H
#define KEYRING_H
#include <stdio.h>
#include "rsa_common_header.h"
#define KEY_TYPE_CRYPT "crypt"
#define KEY_TYPE_SIGN "sign"
#define TYPE_MAX_SIZE 8 

// code de retour : 0 = succès et (-x) = erreurs
#define KR_OK 0
#define KR_ERR_PTR -1 // pointeur nul 
#define KR_ERR_EXISTS -2 // identificateur dejautilisé 
#define KR_ERR_NOTFOUND -3 // identificateur inconnu
#define KR_ERR_TYPAGE -4 // type different de crypt et sign
#define KR_ERR_BADID -5 // identificateur vide 
#define KR_ERR_MEMO -6 // echec du malloc 
#define KR_ERR_KEYGEN -7 // echec lors de la génération de clefs 
#define KR_ERR_FULL -8 // liste pleine (trop de contacts, ou trop de cles pour un contact)
#define KR_ERR_BADTEXT -9 // texte trop long ou sur plusieurs lignes (nom, prenom, commentaire)


//1. entrée de l annuaire 

typedef struct {
    char id[NAME_MAX_SIZE];
    char type[TYPE_MAX_SIZE];
    keyPair_t keys;
}KeyEntry; 

// 1b. contact
#define MAX_CONTACTS 30    
#define MAX_CLES_CONTACT 5    
#define TEXTE_MAX 64  

typedef struct {
    char id[NAME_MAX_SIZE];     
    char type[TYPE_MAX_SIZE];  
    rsaKey_t pubKey;           
} ContactKey;

typedef struct {
    char id[NAME_MAX_SIZE];    
    char nom[TEXTE_MAX];       
    char prenom[TEXTE_MAX];    
    char commentaire[TEXTE_MAX];
    ContactKey cles[MAX_CLES_CONTACT];
    int nb_cles;               
} Contact;

//2. anuuaire : 

typedef struct {
    KeyEntry *entries;
    int count; 
    int capacite;
    Contact contacts[MAX_CONTACTS];   
    int nb_contacts;   
}KeyRing;

int keyring_init (KeyRing *kr);
int keyring_new ( KeyRing *kr , const char *id , const char *type);
int keyring_remove( KeyRing *kr , const char *id );
KeyEntry *keyring_find( KeyRing *kr , const char *id );
void keyring_list (const  KeyRing *kr , const char *id_ou_null );
void keyring_free ( KeyRing *kr);
const char *keyring_erreur( int code);

#endif
