#ifndef IDENTITY_H
#define IDENTITY_H

#include <sodium.h>

/*
 * Each user has an Ed25519 identity key pair. The private key stays on their
 * disk and the public key is exchanged over a trusted channel and stored in
 * contacts.txt (key pinning, like known_hosts in SSH).
 */

typedef struct {
    unsigned char pk[crypto_sign_PUBLICKEYBYTES];
    unsigned char sk[crypto_sign_SECRETKEYBYTES];
} Identity;

/* Loads "<user>.identity" or creates it (mode 0600) along with
 * "<user>.pub.txt". Returns 0 on success (*created = 1 if it was just
 * generated) and -1 on error. */
int load_or_create_identity(const char *username, Identity *id, int *created);

/* Looks up in contacts.txt ("user hex_key" per line) the pinned key of
 * `username`. Returns 0 if found and copies it into out_pk. */
int lookup_contact_pubkey(const char *username, unsigned char *out_pk);

#endif
