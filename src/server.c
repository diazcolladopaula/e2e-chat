/*
 * Messaging server. It only forwards: it knows who is connected and who each
 * message is addressed to, but the payload is opaque to it (it is encrypted
 * end to end), so it cannot read it.
 *
 * Usage: ./server [port] [address]   (defaults: 5555 and 127.0.0.1)
 */
#include "protocol.h"
#include <arpa/inet.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define MAX_CLIENTS 64

typedef struct {
    int sock;
    char username[MAX_USERNAME + 1];
    int active;
} ClientEntry;

static ClientEntry clients[MAX_CLIENTS];
static pthread_mutex_t clients_lock = PTHREAD_MUTEX_INITIALIZER;

/* 0 = registered, -1 = table full, -2 = name already in use */
static int register_client(int sock, const char *username) {
    int rc = -1;
    pthread_mutex_lock(&clients_lock);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].active && strcmp(clients[i].username, username) == 0) {
            pthread_mutex_unlock(&clients_lock);
            return -2;
        }
    }
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (!clients[i].active) {
            clients[i].sock = sock;
            memcpy(clients[i].username, username, strlen(username) + 1);
            clients[i].active = 1;
            rc = 0;
            break;
        }
    }
    pthread_mutex_unlock(&clients_lock);
    return rc;
}

static void unregister_client(int sock) {
    pthread_mutex_lock(&clients_lock);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].active && clients[i].sock == sock) {
            clients[i].active = 0;
            break;
        }
    }
    pthread_mutex_unlock(&clients_lock);
}

/* Forwards the payload untouched. The lock is held during the whole send
 * so the destination socket is not closed halfway and two senders do not
 * interleave frames. Returns 0 on success, -1 if the recipient is not
 * connected and -2 if the send fails. */
static int forward(const char *from, const char *to, const uint8_t *payload, uint32_t plen) {
    int rc = -1;
    pthread_mutex_lock(&clients_lock);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].active && strcmp(clients[i].username, to) == 0) {
            rc = send_frame(clients[i].sock, FRAME_ROUTE, from, payload, plen) == 0 ? 0 : -2;
            break;
        }
    }
    pthread_mutex_unlock(&clients_lock);
    return rc;
}

static void *client_thread(void *arg) {
    int sock = (int)(intptr_t)arg;

    uint8_t type;
    char who[MAX_USERNAME + 1];
    uint8_t payload[MAX_PAYLOAD];
    uint32_t plen;
    char me[MAX_USERNAME + 1] = {0};

    while (recv_frame(sock, &type, who, payload, &plen) == 0) {
        if (type == FRAME_REGISTER) {
            if (me[0]) continue;
            if (plen == 0 || plen > MAX_USERNAME) break;
            char name[MAX_USERNAME + 1];
            memcpy(name, payload, plen);
            name[plen] = '\0';
            if (!valid_username(name)) break;
            int r = register_client(sock, name);
            if (r != 0) {
                fprintf(stderr, "[servidor] registro de '%s' rechazado (%s)\n", name,
                        r == -2 ? "nombre en uso" : "servidor lleno");
                break;
            }
            memcpy(me, name, plen + 1);
            printf("[servidor] '%s' conectado.\n", me);

        } else if (type == FRAME_ROUTE) {
            if (!me[0] || !valid_username(who)) continue;
            int r = forward(me, who, payload, plen);
            if (r == 0) {
                printf("[servidor] %s -> %s: %u bytes opacos\n", me, who, plen);
            } else {
                fprintf(stderr, "[servidor] %s -> %s descartado (%s)\n", me, who,
                        r == -1 ? "destinatario no conectado" : "fallo de envío");
            }
        }
    }

    if (me[0]) {
        unregister_client(sock);
        printf("[servidor] '%s' desconectado.\n", me);
    }
    close(sock);
    return NULL;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    signal(SIGPIPE, SIG_IGN);

    int port = DEFAULT_PORT;
    const char *bind_ip = "127.0.0.1"; /* "0.0.0.0" to accept connections from the network */
    if (argc > 1) port = atoi(argv[1]);
    if (argc > 2) bind_ip = argv[2];
    if (port <= 0 || port > 65535) {
        fprintf(stderr, "Puerto inválido.\nUso: %s [puerto] [direccion]\n", argv[0]);
        return 1;
    }

    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0) { perror("socket"); return 1; }
    int opt = 1;
    setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, bind_ip, &addr.sin_addr) != 1) {
        fprintf(stderr, "Dirección inválida: %s\n", bind_ip);
        return 1;
    }
    if (bind(server_sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) { perror("bind"); return 1; }
    if (listen(server_sock, 16) < 0) { perror("listen"); return 1; }
    printf("[servidor] Escuchando en %s:%d (repetidor ciego, no descifra nada)\n", bind_ip, port);

    while (1) {
        int csock = accept(server_sock, NULL, NULL);
        if (csock < 0) continue;

        pthread_t tid;
        if (pthread_create(&tid, NULL, client_thread, (void *)(intptr_t)csock) != 0) {
            close(csock);
            continue;
        }
        pthread_detach(tid);
    }
}
