CC      ?= gcc
CFLAGS  ?= -O2
CFLAGS  += -std=c11 -D_GNU_SOURCE -Wall -Wextra -Wpedantic \
           -fstack-protector-strong -D_FORTIFY_SOURCE=2
LDLIBS   = -lsodium -lpthread
SRC      = src

all: server client keygen

server: $(SRC)/server.c $(SRC)/protocol.c $(SRC)/protocol.h
	$(CC) $(CFLAGS) -o $@ $(SRC)/server.c $(SRC)/protocol.c $(LDLIBS)

client: $(SRC)/client.c $(SRC)/protocol.c $(SRC)/identity.c $(SRC)/protocol.h $(SRC)/identity.h
	$(CC) $(CFLAGS) -o $@ $(SRC)/client.c $(SRC)/protocol.c $(SRC)/identity.c $(LDLIBS)

keygen: $(SRC)/keygen.c $(SRC)/identity.c $(SRC)/protocol.c $(SRC)/identity.h $(SRC)/protocol.h
	$(CC) $(CFLAGS) -o $@ $(SRC)/keygen.c $(SRC)/identity.c $(SRC)/protocol.c $(LDLIBS)

test_crypto: tests/test_crypto.c
	$(CC) $(CFLAGS) -o $@ tests/test_crypto.c $(LDLIBS)

# Tests: cryptography unit tests + integration (real server and clients)
test: all test_crypto
	./test_crypto
	bash tests/integration.sh

clean:
	rm -f server client keygen test_crypto

# Also deletes generated identities and contacts (including private keys)
distclean: clean
	rm -f *.identity *.pub.txt contacts.txt

.PHONY: all test clean distclean
