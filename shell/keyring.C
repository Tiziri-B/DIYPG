#include <stdio.h>
#include <stdlib.h> 
#include <string.h>
#include "keyring.h"
#include "rsa_keys.h"



//1. fonctions statics pour plus de robustesses 

static int id_valide ( const char *id){
    if( id == NULL ) return 0 ; 
    size_t longueur = strlen(id);
    if( longueur ==0 || longueur >= NAME_MAX_SIZE ) return 0 ; 
    for(size_t i = 0 ; i< longueur ; i++){
      {
        if(id[i] == ' ' || id[i] == '\t' || id[i] == '/') {
         return 0;
      }
    } 
    }
    return 1;
     
}



static int type_valide(const char *type){
    return type != NULL && ( strcmp(type, KEY_TYPE_CRYPT) == 0 || strcmp(type, KEY_TYPE_SIGN) == 0 );
}


static int generer_paire(keyPair_t *kp) {
    return generateKeysBlock(&kp->pubKey, &kp->privKey);
}

// 2. fonction de l annuaire 

int keyring_init (KeyRing *kr){ // initialise l annuaire vide 
    if( kr == NULL ) return KR_ERR_PTR ; 
    kr->entries = NULL;
    kr->count = 0;
    kr->capacite = 0 ;
    return KR_OK;
}

void keyring_free ( KeyRing *kr) {
    if (kr == NULL ) return ; 
    if(kr->entries != NULL){
        free(kr->entries);
        kr->entries = NULL;
    }
    kr->count = 0 ;
    kr->capacite = 0 ;
}

KeyEntry *keyring_find( KeyRing *kr , const char *id ){
    if(kr == NULL || id == NULL) return NULL;
    for (int i = 0 ; i < kr->count; i++) {
        if(strcmp(kr->entries[i].id , id) == 0 ){
            return &(kr->entries[i]);
        }
    }
    return NULL;
}

void keyring_list (const  KeyRing *kr , const char *id_ou_null ){
     if(kr == NULL) return ; 
     for( int  i= 0 ; i< kr->count; i++){
        if(id_ou_null == NULL || strcmp(kr->entries[i].id ,id_ou_null)== 0 ){
            printf("ID : %-15s | type  : %s\n" , kr->entries[i].id, kr->entries[i].type);
        }
     }
}

int keyring_new ( KeyRing *kr , const char *id , const char *type){
    if( kr == NULL || id == NULL || type == NULL) return KR_ERR_PTR;
    if(!id_valide(id)) return KR_ERR_BADID;
    if(!type_valide(type)) return KR_ERR_TYPAGE;
    if(keyring_find(kr, id) != NULL) return KR_ERR_EXISTS;


     // si le tableau est plein , on doit le redimentionné 
     if(kr->count >= kr->capacite){
        int nv_cap = (kr->capacite == 0) ? 4 : kr->capacite *2; 
        KeyEntry *temp = realloc(kr->entries , nv_cap *sizeof(KeyEntry));
        if(temp == NULL) return KR_ERR_MEMO;
        kr->entries  =temp;
        kr->capacite = nv_cap;
     }

     // la case libre = entry
     KeyEntry *entry = &(kr->entries[kr->count]);

     
     strncpy(entry->id , id , NAME_MAX_SIZE -1);
     entry->id[NAME_MAX_SIZE -1] = '\0';

     strncpy(entry->type, type , TYPE_MAX_SIZE -1);
     entry->type[TYPE_MAX_SIZE -1] = '\0';
      
     // generer une paire de cle 
     if(generer_paire(&(entry->keys)) != 0){
        return KR_ERR_KEYGEN;
     }

    kr->count++;
    return KR_OK;
}
int keyring_remove( KeyRing *kr , const char *id ){
    if(kr == NULL || id == NULL) return KR_ERR_PTR;


    int index = -1;
    for( int i = 0 ; i < kr->count ; i++){
        if(strcmp(kr->entries[i].id , id) == 0 ){
            index = i;
        }
    }

    if(index == -1) return KR_ERR_NOTFOUND; 

     // decalge des elements 
     for(int i = index ; i < kr->count -1 ; i++){
        kr->entries[i]= kr->entries[i+1];
     }
     kr->count--;
     return KR_OK;
}

const char *keyring_erreur( int code){
    switch(code){
        case KR_OK : return "succes";
        case KR_ERR_PTR : return " erreur : ptr null ou invalide";
        case KR_ERR_EXISTS : return "erreur id deja existants";
        case KR_ERR_NOTFOUND : return " erreur : id pas trouve";
        case KR_ERR_TYPAGE: return " erreur : type invalide";
        case KR_ERR_BADID : return " erreur de l id ";
        case KR_ERR_MEMO : return " erreur de l alloc memo";
        case KR_ERR_KEYGEN : return "erreur de la generation de la paire de clefs";
        default : return " autre erreur";
    }
}
