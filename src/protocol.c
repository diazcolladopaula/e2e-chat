#include "protocol.h"
#include <arpa/inet.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int valid_username(const char *s) {
    if (!s) return 0;
    size_t n = strlen(s);
    if (n == 0 || n > MAX_USERNAME) return 0;
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        int ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                 (c >= '0' && c <= '9') || c == '_' || c == '-';
        if (!ok) return 0;
    }
    return 1;
}

/* send/read may transfer fewer bytes than requested, so they are repeated
 * until n bytes are done. MSG_NOSIGNAL avoids SIGPIPE when writing to a closed socket. */
static int write_all(int sock, const void *buf, size_t n) {
    const uint8_t *p = buf;
    size_t sent = 0;
    while (sent < n) {
        ssize_t w = send(sock, p + sent, n - sent, MSG_NOSIGNAL);
        if (w <= 0) return -1;
        sent += (size_t)w;
    }
    return 0;
}

static int read_all(int sock, void *buf, size_t n) {
    uint8_t *p = buf;
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(sock, p + got, n - got);
        if (r <= 0) return -1;
        got += (size_t)r;
    }
    return 0;
}

int send_frame(int sock, uint8_t type, const char *who, const uint8_t *payload, uint32_t payload_len) {
    if (payload_len > MAX_PAYLOAD) return -1;
    uint8_t who_len = who ? (uint8_t)strnlen(who, MAX_USERNAME) : 0;
    uint32_t plen_be = htonl(payload_len);

    if (write_all(sock, &type, 1) != 0) return -1;
    if (write_all(sock, &who_len, 1) != 0) return -1;
    if (who_len > 0 && write_all(sock, who, who_len) != 0) return -1;
    if (write_all(sock, &plen_be, 4) != 0) return -1;
    if (payload_len > 0 && write_all(sock, payload, payload_len) != 0) return -1;
    return 0;
}

int recv_frame(int sock, uint8_t *type_out, char *who, uint8_t *payload, uint32_t *payload_len_out) {
    uint8_t type, who_len;
    uint32_t plen_be, plen;

    if (read_all(sock, &type, 1) != 0) return -1;
    if (read_all(sock, &who_len, 1) != 0) return -1;

    /* who_len comes from the network and can be up to 255; the caller's buffer
     * only holds MAX_USERNAME+1 bytes */
    if (who_len > MAX_USERNAME) return -1;
    if (who_len > 0 && read_all(sock, who, who_len) != 0) return -1;
    who[who_len] = '\0';

    if (read_all(sock, &plen_be, 4) != 0) return -1;
    plen = ntohl(plen_be);
    if (plen > MAX_PAYLOAD) return -1;
    if (plen > 0 && read_all(sock, payload, plen) != 0) return -1;

    *type_out = type;
    *payload_len_out = plen;
    return 0;
}
