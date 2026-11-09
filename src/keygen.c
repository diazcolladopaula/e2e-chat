/* Creates (or loads) a user's identity and prints its public key.
 * Usage: ./keygen <user> */
#include "identity.h"
#include <stdio.h>

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Uso: %s <usuario>\n", argv[0]);
        return 1;
    }
    if (sodium_init() < 0) {
        fprintf(stderr, "No se pudo inicializar libsodium\n");
        return 1;
    }
    Identity id;
    int created;
    if (load_or_create_identity(argv[1], &id, &created) != 0) {
        fprintf(stderr, "Usuario inválido (letras, números, '_' o '-', máx. 32) o error de disco.\n");
        return 1;
    }
    char hex[crypto_sign_PUBLICKEYBYTES * 2 + 1];
    sodium_bin2hex(hex, sizeof(hex), id.pk, sizeof(id.pk));
    fprintf(stderr, created ? "Identidad creada para '%s'. " : "Identidad existente de '%s'. ", argv[1]);
    fprintf(stderr, "Clave pública:\n");
    printf("%s\n", hex);
    sodium_memzero(id.sk, sizeof(id.sk));
    return 0;
}
