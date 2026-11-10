#include <stdlib.h>
#include <time.h>
#include "../shell/keyring.h"
#include "../shell/interpreter.h"

int main(void) {
    srand((unsigned int)time(NULL));

    KeyRing annuaire;
    keyring_init(&annuaire);
    
    int code=interpreter_run(&annuaire);

    keyring_free(&annuaire);

    return code;
}