#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdint.h>
#include <stddef.h>

#define DEFAULT_PORT 5555
#define MAX_USERNAME 32
#define MAX_PAYLOAD 8192

/*
 * Frames between client and server (the server only understands this level):
 *
 *   client -> server: [type:1][to_len:1][to][payload_len:4 BE][payload]
 *   server -> client: [type:1][from_len:1][from][payload_len:4 BE][payload]
 *
 *   FRAME_REGISTER  payload = the sender's own username
 *   FRAME_ROUTE     payload = opaque message for "to"; the server forwards it
 *                   with the user who registered the connection as the sender
 */
#define FRAME_REGISTER 0x01
#define FRAME_ROUTE    0x02

/*
 * First byte of the payload (only clients interpret it):
 *   APP_HANDSHAKE  [0xA1][ephemeral X25519 key: 32][Ed25519 signature: 64]
 *   APP_DATA       [0xA2][seq u64 BE: 8][nonce: 24][ciphertext + tag: 16]
 */
#define APP_HANDSHAKE 0xA1
#define APP_DATA      0xA2

/* 1 if the name is 1 to MAX_USERNAME characters long, all from [A-Za-z0-9_-] */
int valid_username(const char *s);

/* Return 0 on success and -1 on error. send_frame is not thread-safe: the
 * caller must serialize sends on the same socket.
 * recv_frame's `who` needs MAX_USERNAME+1 bytes and `payload` needs MAX_PAYLOAD. */
int send_frame(int sock, uint8_t type, const char *who, const uint8_t *payload, uint32_t payload_len);
int recv_frame(int sock, uint8_t *type_out, char *who, uint8_t *payload, uint32_t *payload_len_out);

#endif
