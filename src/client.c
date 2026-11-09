/*
 * End-to-end encrypted chat client. All the cryptography lives here; the
 * server only sees opaque bytes.
 *
 * Protocol between two users:
 *
 *  1. Handshake: each side generates an ephemeral X25519 pair and signs with its
 *     Ed25519 identity
 *         "e2echat-hs-v1" || sender || recipient || ephemeral_key
 *     The names and the label bind the signature to its context.
 *
 *  2. Verification: the other side's signature is checked with its identity key,
 *     which must be pinned in contacts.txt. If it does not match, it is rejected.
 *
 *  3. Session keys: crypto_kx derives one key per direction (tx/rx). The
 *     crypto_kx client/server role is decided by alphabetical order of the names.
 *
 *  4. Messages: XChaCha20-Poly1305 with
 *         [APP_DATA][seq u64][nonce 24 B][ciphertext + tag]
 *     [APP_DATA][seq] goes as associated data (authenticated). Any seq that is
 *     not greater than the previous one is rejected (replays and reordering).
 *
 * Ephemeral keys only exist in memory.
 */
#include "identity.h"
#include "protocol.h"

#include <arpa/inet.h>
#include <pthread.h>
#include <signal.h>
#include <sodium.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define SEQ_BYTES 8
#define NONCE_BYTES crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
#define TAG_BYTES crypto_aead_xchacha20poly1305_ietf_ABYTES
#define MAX_MSG 4096
#define DATA_HDR (1 + SEQ_BYTES)

#define HS_LABEL "e2echat-hs-v1"
#define HS_LABEL_LEN (sizeof(HS_LABEL) - 1)
#define HS_BLOB_LEN (HS_LABEL_LEN + 2 * MAX_USERNAME + crypto_kx_PUBLICKEYBYTES)
#define HANDSHAKE_PAYLOAD_LEN (1 + crypto_kx_PUBLICKEYBYTES + crypto_sign_BYTES)
#define HANDSHAKE_TIMEOUT_S 120

typedef struct {
    int sock;
    char me[MAX_USERNAME + 1];
    char peer[MAX_USERNAME + 1];

    Identity id;
    unsigned char peer_id_pk[crypto_sign_PUBLICKEYBYTES]; /* the other side's pinned key */

    unsigned char kx_pk[crypto_kx_PUBLICKEYBYTES];        /* ephemeral pair */
    unsigned char kx_sk[crypto_kx_SECRETKEYBYTES];
    unsigned char hs_payload[HANDSHAKE_PAYLOAD_LEN];      /* own handshake, ready to resend */

    unsigned char rx[crypto_kx_SESSIONKEYBYTES];
    unsigned char tx[crypto_kx_SESSIONKEYBYTES];
    uint64_t tx_seq;    /* main thread only */
    uint64_t rx_last;   /* receiver thread only */
    int rx_seen;

    atomic_int ready;
    pthread_mutex_t send_lock;
} Session;

static Session S;

/* ---------- Handshake ---------- */

static void build_hs_blob(unsigned char *blob, const char *from, const char *to, const unsigned char *eph_pk) {
    size_t off = 0;
    memset(blob, 0, HS_BLOB_LEN);
    memcpy(blob + off, HS_LABEL, HS_LABEL_LEN);
    off += HS_LABEL_LEN;
    memcpy(blob + off, from, strlen(from));
    off += MAX_USERNAME;
    memcpy(blob + off, to, strlen(to));
    off += MAX_USERNAME;
    memcpy(blob + off, eph_pk, crypto_kx_PUBLICKEYBYTES);
}

static void prepare_handshake(Session *s) {
    crypto_kx_keypair(s->kx_pk, s->kx_sk);

    unsigned char blob[HS_BLOB_LEN];
    build_hs_blob(blob, s->me, s->peer, s->kx_pk);

    unsigned char sig[crypto_sign_BYTES];
    crypto_sign_detached(sig, NULL, blob, sizeof(blob), s->id.sk);

    s->hs_payload[0] = APP_HANDSHAKE;
    memcpy(s->hs_payload + 1, s->kx_pk, crypto_kx_PUBLICKEYBYTES);
    memcpy(s->hs_payload + 1 + crypto_kx_PUBLICKEYBYTES, sig, crypto_sign_BYTES);
}

static void send_handshake(Session *s) {
    static int announced = 0;
    pthread_mutex_lock(&s->send_lock);
    send_frame(s->sock, FRAME_ROUTE, s->peer, s->hs_payload, HANDSHAKE_PAYLOAD_LEN);
    if (!announced) {
        announced = 1;
        printf("[handshake] Enviada clave efímera firmada a '%s'.\n", s->peer);
    }
    pthread_mutex_unlock(&s->send_lock);
}

/* Verifies the other side's handshake and derives the session keys. 0 = OK. */
static int process_handshake(Session *s, const uint8_t *payload, uint32_t plen) {
    if (plen != HANDSHAKE_PAYLOAD_LEN || payload[0] != APP_HANDSHAKE) {
        fprintf(stderr, "[handshake] Formato inesperado, descartado.\n");
        return -1;
    }
    const unsigned char *peer_eph_pk = payload + 1;
    const unsigned char *sig = payload + 1 + crypto_kx_PUBLICKEYBYTES;

    unsigned char blob[HS_BLOB_LEN];
    build_hs_blob(blob, s->peer, s->me, peer_eph_pk);
    if (crypto_sign_verify_detached(sig, blob, sizeof(blob), s->peer_id_pk) != 0) {
        fprintf(stderr, "[handshake][ALERTA] Firma de '%s' INVÁLIDA: posible "
                        "man-in-the-middle o clave pineada incorrecta. Rechazado.\n", s->peer);
        return -1;
    }
    printf("[handshake] Firma de '%s' verificada correctamente. Identidad auténtica.\n", s->peer);

    int rc;
    if (strcmp(s->me, s->peer) < 0) {
        rc = crypto_kx_client_session_keys(s->rx, s->tx, s->kx_pk, s->kx_sk, peer_eph_pk);
    } else {
        rc = crypto_kx_server_session_keys(s->rx, s->tx, s->kx_pk, s->kx_sk, peer_eph_pk);
    }
    if (rc != 0) {
        fprintf(stderr, "[handshake] Clave efímera del otro lado inválida.\n");
        return -1;
    }

    sodium_memzero(s->kx_sk, sizeof(s->kx_sk));
    atomic_store(&s->ready, 1);
    printf("[handshake] Claves de sesión derivadas. Canal cifrado E2E establecido con '%s'.\n", s->peer);
    return 0;
}

/* ---------- Messages ---------- */

static void send_message(Session *s, const char *text) {
    size_t mlen = strlen(text);
    unsigned char payload[DATA_HDR + NONCE_BYTES + MAX_MSG + TAG_BYTES];

    uint64_t seq = ++s->tx_seq;
    payload[0] = APP_DATA;
    for (int i = 0; i < SEQ_BYTES; i++) payload[1 + i] = (unsigned char)(seq >> (56 - 8 * i));
    unsigned char *nonce = payload + DATA_HDR;
    randombytes_buf(nonce, NONCE_BYTES);

    unsigned long long clen;
    crypto_aead_xchacha20poly1305_ietf_encrypt(
        nonce + NONCE_BYTES, &clen,
        (const unsigned char *)text, mlen,
        payload, DATA_HDR, /* associated data: type + seq */
        NULL, nonce, s->tx);

    pthread_mutex_lock(&s->send_lock);
    send_frame(s->sock, FRAME_ROUTE, s->peer, payload, (uint32_t)(DATA_HDR + NONCE_BYTES + clen));
    pthread_mutex_unlock(&s->send_lock);
}

static int receive_message(Session *s, const uint8_t *p, uint32_t plen, char *out) {
    if (plen < DATA_HDR + NONCE_BYTES + TAG_BYTES) return -1;
    size_t clen = plen - DATA_HDR - NONCE_BYTES;
    if (clen - TAG_BYTES > MAX_MSG) return -1;

    uint64_t seq = 0;
    for (int i = 0; i < SEQ_BYTES; i++) seq = (seq << 8) | p[1 + i];
    const unsigned char *nonce = p + DATA_HDR;

    unsigned long long mlen;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            (unsigned char *)out, &mlen, NULL,
            nonce + NONCE_BYTES, clen,
            p, DATA_HDR, nonce, s->rx) != 0) {
        fprintf(stderr, "\n[cifrado][ALERTA] Fallo de autenticación: mensaje manipulado o clave incorrecta. Descartado.\n");
        return -1;
    }
    /* the sequence number is checked after authenticating */
    if (s->rx_seen && seq <= s->rx_last) {
        fprintf(stderr, "\n[cifrado][ALERTA] Mensaje repetido o fuera de orden (seq %llu). Descartado.\n",
                (unsigned long long)seq);
        return -1;
    }
    s->rx_seen = 1;
    s->rx_last = seq;
    out[mlen] = '\0';
    return 0;
}

static void *listener_thread(void *arg) {
    Session *s = arg;
    uint8_t type;
    char who[MAX_USERNAME + 1];
    uint8_t payload[MAX_PAYLOAD];
    uint32_t plen;

    while (recv_frame(s->sock, &type, who, payload, &plen) == 0) {
        if (type != FRAME_ROUTE || plen == 0) continue;
        if (strcmp(who, s->peer) != 0) continue;

        if (payload[0] == APP_HANDSHAKE) {
            /* the handshake is resent every second; ignored once there is a session */
            if (!atomic_load(&s->ready) && process_handshake(s, payload, plen) == 0) {
                /* reply with our own so the other side can complete too */
                send_handshake(s);
            }
        } else if (payload[0] == APP_DATA && atomic_load(&s->ready)) {
            char text[MAX_MSG + 1];
            if (receive_message(s, payload, plen, text) == 0) {
                printf("\r[%s] %s\n> ", s->peer, text);
                fflush(stdout);
            }
        }
    }
    printf("\n[cliente] Conexión con el servidor perdida.\n");
    exit(1);
}

/* ---------- main ---------- */

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "Uso: %s <mi_usuario> <usuario_destino> <ip_servidor> [puerto]\n", argv[0]);
        return 1;
    }
    setvbuf(stdout, NULL, _IOLBF, 0);
    signal(SIGPIPE, SIG_IGN);
    if (sodium_init() < 0) {
        fprintf(stderr, "No se pudo inicializar libsodium\n");
        return 1;
    }

    const char *me = argv[1], *peer = argv[2], *server_ip = argv[3];
    int port = argc > 4 ? atoi(argv[4]) : DEFAULT_PORT;
    if (!valid_username(me) || !valid_username(peer) || strcmp(me, peer) == 0) {
        fprintf(stderr, "Usuarios inválidos: deben ser distintos y usar letras, números, '_' o '-' (máx. 32).\n");
        return 1;
    }

    memset(&S, 0, sizeof(S));
    pthread_mutex_init(&S.send_lock, NULL);
    snprintf(S.me, sizeof(S.me), "%s", me);
    snprintf(S.peer, sizeof(S.peer), "%s", peer);

    int created;
    if (load_or_create_identity(me, &S.id, &created) != 0) {
        fprintf(stderr, "No se pudo cargar o crear la identidad de '%s'.\n", me);
        return 1;
    }
    if (created) {
        char hex[crypto_sign_PUBLICKEYBYTES * 2 + 1];
        sodium_bin2hex(hex, sizeof(hex), S.id.pk, sizeof(S.id.pk));
        printf("[identidad] Nueva identidad creada para '%s'.\n[identidad] Clave pública:\n  %s\n", me, hex);
    }

    if (lookup_contact_pubkey(peer, S.peer_id_pk) != 0) {
        fprintf(stderr,
                "\nNo hay clave pública de '%s' en contacts.txt.\n"
                "Añádela con:  echo \"%s <clave_hex>\" >> contacts.txt\n\n", peer, peer);
        return 1;
    }

    S.sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    if (S.sock < 0 || inet_pton(AF_INET, server_ip, &addr.sin_addr) != 1) {
        fprintf(stderr, "Dirección de servidor inválida: %s\n", server_ip);
        return 1;
    }
    if (connect(S.sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect");
        return 1;
    }
    send_frame(S.sock, FRAME_REGISTER, NULL, (const uint8_t *)me, (uint32_t)strlen(me));

    /* the ephemeral keys must exist before the receiver thread starts */
    prepare_handshake(&S);
    pthread_t tid;
    pthread_create(&tid, NULL, listener_thread, &S);

    /* if the other side is not connected yet the server drops the handshake,
     * so it is retried every second */
    printf("[handshake] Esperando a que '%s' se conecte...\n", peer);
    for (int i = 0; i < HANDSHAKE_TIMEOUT_S && !atomic_load(&S.ready); i++) {
        send_handshake(&S);
        sleep(1);
    }
    if (!atomic_load(&S.ready)) {
        fprintf(stderr, "[handshake] No se estableció sesión con '%s'. Revisa contacts.txt y reinicia.\n", peer);
        return 1;
    }

    printf("Escribe mensajes para '%s' (Ctrl+C para salir):\n> ", peer);
    fflush(stdout);

    char line[MAX_MSG];
    while (fgets(line, sizeof(line), stdin)) {
        line[strcspn(line, "\n")] = '\0';
        if (line[0] != '\0') send_message(&S, line);
        printf("> ");
        fflush(stdout);
    }

    close(S.sock);
    sodium_memzero(S.id.sk, sizeof(S.id.sk));
    sodium_memzero(S.tx, sizeof(S.tx));
    sodium_memzero(S.rx, sizeof(S.rx));
    return 0;
}
