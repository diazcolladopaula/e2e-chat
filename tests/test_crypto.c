/*
 * Unit test of the primitives and the protocol design, in a single
 * process and without a network: it simulates alice and bob and checks the
 * security properties. The tests with the real client and server are in
 * integration.sh.
 */
#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures = 0;

#define CHECK(cond, msg)                                              \
    do {                                                              \
        if (cond) printf("  [OK]    %s\n", msg);                      \
        else { printf("  [FALLO] %s\n", msg); failures++; }           \
    } while (0)

int main(void) {
    if (sodium_init() < 0) { fprintf(stderr, "fallo sodium_init\n"); return 1; }

    printf("=== 1. Identidades a largo plazo (Ed25519) ===\n");
    unsigned char a_pk[crypto_sign_PUBLICKEYBYTES], a_sk[crypto_sign_SECRETKEYBYTES];
    unsigned char b_pk[crypto_sign_PUBLICKEYBYTES], b_sk[crypto_sign_SECRETKEYBYTES];
    crypto_sign_keypair(a_pk, a_sk);
    crypto_sign_keypair(b_pk, b_sk);
    CHECK(1, "Identidades de alice y bob generadas");

    printf("=== 2. Handshake: claves efímeras X25519 firmadas ===\n");
    unsigned char a_kx_pk[crypto_kx_PUBLICKEYBYTES], a_kx_sk[crypto_kx_SECRETKEYBYTES];
    unsigned char b_kx_pk[crypto_kx_PUBLICKEYBYTES], b_kx_sk[crypto_kx_SECRETKEYBYTES];
    crypto_kx_keypair(a_kx_pk, a_kx_sk);
    crypto_kx_keypair(b_kx_pk, b_kx_sk);
    unsigned char a_sig[crypto_sign_BYTES], b_sig[crypto_sign_BYTES];
    crypto_sign_detached(a_sig, NULL, a_kx_pk, sizeof(a_kx_pk), a_sk);
    crypto_sign_detached(b_sig, NULL, b_kx_pk, sizeof(b_kx_pk), b_sk);
    CHECK(crypto_sign_verify_detached(a_sig, a_kx_pk, sizeof(a_kx_pk), a_pk) == 0 &&
          crypto_sign_verify_detached(b_sig, b_kx_pk, sizeof(b_kx_pk), b_pk) == 0,
          "Cada lado verifica la firma del otro con su identidad pineada");

    printf("=== 3. Suplantación (man-in-the-middle) ===\n");
    unsigned char m_kx_pk[crypto_kx_PUBLICKEYBYTES], m_kx_sk[crypto_kx_SECRETKEYBYTES];
    crypto_kx_keypair(m_kx_pk, m_kx_sk);
    CHECK(crypto_sign_verify_detached(b_sig, m_kx_pk, sizeof(m_kx_pk), b_pk) != 0,
          "Mallory no puede reutilizar la firma de bob con su propia clave efímera");
    unsigned char m_pk[crypto_sign_PUBLICKEYBYTES], m_sk[crypto_sign_SECRETKEYBYTES];
    unsigned char m_sig[crypto_sign_BYTES];
    crypto_sign_keypair(m_pk, m_sk);
    crypto_sign_detached(m_sig, NULL, m_kx_pk, sizeof(m_kx_pk), m_sk);
    CHECK(crypto_sign_verify_detached(m_sig, m_kx_pk, sizeof(m_kx_pk), b_pk) != 0,
          "Mallory no puede firmar con SU identidad y hacerse pasar por la de bob");

    printf("=== 4. Derivación de claves de sesión (crypto_kx) ===\n");
    unsigned char a_rx[crypto_kx_SESSIONKEYBYTES], a_tx[crypto_kx_SESSIONKEYBYTES];
    unsigned char b_rx[crypto_kx_SESSIONKEYBYTES], b_tx[crypto_kx_SESSIONKEYBYTES];
    int rc1 = crypto_kx_client_session_keys(a_rx, a_tx, a_kx_pk, a_kx_sk, b_kx_pk);
    int rc2 = crypto_kx_server_session_keys(b_rx, b_tx, b_kx_pk, b_kx_sk, a_kx_pk);
    CHECK(rc1 == 0 && rc2 == 0, "Ambos lados derivan claves de sesión");
    CHECK(memcmp(a_tx, b_rx, sizeof(a_tx)) == 0 && memcmp(b_tx, a_rx, sizeof(b_tx)) == 0,
          "TX de alice == RX de bob y TX de bob == RX de alice");
    CHECK(memcmp(a_tx, a_rx, sizeof(a_tx)) != 0, "Las claves de cada sentido son distintas (evita reflexión)");

    printf("=== 5. Cifrado autenticado (XChaCha20-Poly1305) con cabecera autenticada ===\n");
    const char *msg = "Hola Bob, esto es un mensaje secreto";
    unsigned char hdr[9] = {0xA2, 0, 0, 0, 0, 0, 0, 0, 1}; /* type + seq=1 as AAD */
    unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    randombytes_buf(nonce, sizeof(nonce));
    unsigned char ct[256], pt[256];
    unsigned long long clen, mlen;
    crypto_aead_xchacha20poly1305_ietf_encrypt(ct, &clen, (const unsigned char *)msg, strlen(msg),
                                               hdr, sizeof(hdr), NULL, nonce, a_tx);
    printf("  Texto plano : \"%s\"\n  Cifrado (hex): ", msg);
    for (int i = 0; i < 16; i++) printf("%02x", ct[i]);
    printf("...\n");
    int dec = crypto_aead_xchacha20poly1305_ietf_decrypt(pt, &mlen, NULL, ct, clen, hdr, sizeof(hdr), nonce, b_rx);
    CHECK(dec == 0 && mlen == strlen(msg) && memcmp(pt, msg, mlen) == 0, "Bob descifra exactamente el mensaje de alice");

    printf("=== 6. Integridad y anti-repetición ===\n");
    unsigned char ct2[256];
    memcpy(ct2, ct, clen);
    ct2[0] ^= 0x01;
    CHECK(crypto_aead_xchacha20poly1305_ietf_decrypt(pt, &mlen, NULL, ct2, clen, hdr, sizeof(hdr), nonce, b_rx) != 0,
          "Un solo bit alterado en el texto cifrado: rechazado");
    unsigned char hdr2[9];
    memcpy(hdr2, hdr, sizeof(hdr));
    hdr2[8] = 2; /* an attacker changes the sequence number */
    CHECK(crypto_aead_xchacha20poly1305_ietf_decrypt(pt, &mlen, NULL, ct, clen, hdr2, sizeof(hdr2), nonce, b_rx) != 0,
          "Alterar el número de secuencia (cabecera autenticada): rechazado");
    CHECK(crypto_aead_xchacha20poly1305_ietf_decrypt(pt, &mlen, NULL, ct, clen, hdr, sizeof(hdr), nonce, a_rx) != 0,
          "Descifrar con la clave equivocada: rechazado");

    printf("\n%s\n", failures == 0 ? "=== TODAS LAS PRUEBAS PASARON ===" : "=== HAY PRUEBAS FALLIDAS ===");
    return failures == 0 ? 0 : 1;
}
