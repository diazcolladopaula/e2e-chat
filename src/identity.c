#include "identity.h"
#include "protocol.h"
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

int load_or_create_identity(const char *username, Identity *id, int *created) {
    if (created) *created = 0;
    if (!valid_username(username)) return -1; /* the name ends up in a file path */

    char path[128];
    snprintf(path, sizeof(path), "%s.identity", username);

    FILE *f = fopen(path, "rb");
    if (f) {
        size_t r1 = fread(id->pk, 1, sizeof(id->pk), f);
        size_t r2 = fread(id->sk, 1, sizeof(id->sk), f);
        fclose(f);
        if (r1 == sizeof(id->pk) && r2 == sizeof(id->sk)) return 0;
        fprintf(stderr, "[identidad] '%s' está corrupto, se regenera.\n", path);
    }

    crypto_sign_keypair(id->pk, id->sk);

    /* permissions are restricted before writing the private key */
    f = fopen(path, "wb");
    if (!f) return -1;
    if (chmod(path, S_IRUSR | S_IWUSR) != 0) { fclose(f); return -1; }
    if (fwrite(id->pk, 1, sizeof(id->pk), f) != sizeof(id->pk) ||
        fwrite(id->sk, 1, sizeof(id->sk), f) != sizeof(id->sk)) {
        fclose(f);
        return -1;
    }
    fclose(f);

    char hex[crypto_sign_PUBLICKEYBYTES * 2 + 1];
    sodium_bin2hex(hex, sizeof(hex), id->pk, sizeof(id->pk));
    char pubpath[128];
    snprintf(pubpath, sizeof(pubpath), "%s.pub.txt", username);
    FILE *pf = fopen(pubpath, "w");
    if (pf) {
        fprintf(pf, "%s\n", hex);
        fclose(pf);
    }
    if (created) *created = 1;
    return 0;
}

int lookup_contact_pubkey(const char *username, unsigned char *out_pk) {
    FILE *f = fopen("contacts.txt", "r");
    if (!f) return -1;

    char line[256];
    int found = -1;
    while (fgets(line, sizeof(line), f)) {
        char name[64], hex[128];
        if (sscanf(line, "%63s %127s", name, hex) != 2) continue;
        if (strcmp(name, username) != 0) continue;
        size_t binlen = 0;
        if (sodium_hex2bin(out_pk, crypto_sign_PUBLICKEYBYTES, hex, strlen(hex),
                           NULL, &binlen, NULL) == 0 && binlen == crypto_sign_PUBLICKEYBYTES) {
            found = 0;
        }
        break; /* only the first entry counts: if a contact's key changes, it should raise an alert */
    }
    fclose(f);
    return found;
}
