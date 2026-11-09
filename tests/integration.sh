#!/usr/bin/env bash
# Integration tests with the real server and clients, including
# simulated attacks. Each user works in their own directory with their
# own contacts.txt.
# Usage: tests/integration.sh   (~35 s; port 5599 by default, override with PORT=...)

set -u
trap '' PIPE   # the server closes malicious connections and writing to them would raise SIGPIPE
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PORT="${PORT:-5599}"
TMP="$(mktemp -d)"
PASS=0; FAIL=0; SERVER_PID=""

cleanup() { [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null; rm -rf "$TMP"; }
trap cleanup EXIT

ok()   { echo "  [OK]    $1"; PASS=$((PASS+1)); }
bad()  { echo "  [FALLO] $1"; FAIL=$((FAIL+1)); }
has()  { grep -qF -- "$2" "$1"; }                    # has <file> <text>
check(){ if "$@" >/dev/null 2>&1; then return 0; else return 1; fi; }

for bin in server client keygen; do
    [ -x "$ROOT/$bin" ] || { echo "Falta '$bin': ejecuta 'make' primero."; exit 2; }
done

mkdir -p "$TMP"/{alice,bob,mallory}
for u in alice bob mallory; do (cd "$TMP/$u" && "$ROOT/keygen" "$u" >/dev/null 2>&1); done
echo "bob $(cat "$TMP/bob/bob.pub.txt")"     > "$TMP/alice/contacts.txt"
echo "alice $(cat "$TMP/alice/alice.pub.txt")" > "$TMP/bob/contacts.txt"

"$ROOT/server" "$PORT" 127.0.0.1 > "$TMP/server.log" 2>&1 &
SERVER_PID=$!
sleep 0.7

# run_client <user> <peer> <lifetime_s> <msg_delay_s> <message>  (in the background)
run_client() {
    local user="$1" peer="$2" life="$3" delay="$4" msg="$5"
    ( ( sleep "$delay"; [ -n "$msg" ] && echo "$msg"; sleep 3 ) |
      ( cd "$TMP/$user" && timeout "$life" "$ROOT/client" "$user" "$peer" 127.0.0.1 "$PORT" ) \
      > "$TMP/$user.log" 2>&1 ) &
}

echo "== 1. Chat legítimo (Alice arranca 2 s antes que Bob) =="
run_client alice bob 14 8 "Hola Bob, mensaje-secreto-123"; A=$!
sleep 2
run_client bob alice 12 6 "Hola Alice, te leo"; B=$!
wait $A $B
has "$TMP/alice.log" "Canal cifrado E2E establecido con 'bob'"   && ok "Alice establece el canal cifrado"      || bad "Alice no establece el canal"
has "$TMP/bob.log"   "Canal cifrado E2E establecido con 'alice'" && ok "Bob establece el canal cifrado"        || bad "Bob no establece el canal"
has "$TMP/bob.log"   "[alice] Hola Bob, mensaje-secreto-123"      && ok "Bob recibe y descifra el mensaje de Alice" || bad "Bob no recibió el mensaje"
has "$TMP/alice.log" "[bob] Hola Alice, te leo"                   && ok "Alice recibe y descifra la respuesta"  || bad "Alice no recibió la respuesta"
if grep -q "ALERTA" "$TMP/alice.log" "$TMP/bob.log"; then bad "Aparecieron alertas de seguridad falsas"; else ok "Sin alertas falsas en un uso legítimo"; fi

echo "== 2. Servidor ciego: no ve el contenido =="
if grep -q "mensaje-secreto-123" "$TMP/server.log"; then bad "El texto en claro aparece en el log del servidor"; else ok "El log del servidor no contiene el texto en claro"; fi
has "$TMP/server.log" "alice -> bob" && ok "El servidor solo registra metadatos (quién -> quién, tamaño)" || bad "El servidor no registró el reenvío"

echo "== 3. Tramas malformadas / maliciosas contra el servidor =="
# a) 255-byte recipient name
{ exec 3<>"/dev/tcp/127.0.0.1/$PORT"; printf '\x02\xff' >&3; head -c 255 /dev/zero | tr '\0' 'A' >&3; printf '\x00\x00\x00\x00' >&3; exec 3>&-; } 2>/dev/null
# b) payload length 0xFFFFFFFF
{ exec 3<>"/dev/tcp/127.0.0.1/$PORT"; printf '\x02\x00\xff\xff\xff\xff' >&3; exec 3>&-; } 2>/dev/null
# c) random bytes
{ exec 3<>"/dev/tcp/127.0.0.1/$PORT"; head -c 512 /dev/urandom >&3; exec 3>&-; } 2>/dev/null
sleep 0.5
kill -0 "$SERVER_PID" 2>/dev/null && ok "El servidor sigue vivo tras recibir tramas maliciosas" || bad "El servidor se cayó"

echo "== 4. Ataque man-in-the-middle: Bob tiene pineada una clave falsa para 'alice' =="
echo "alice $(cat "$TMP/mallory/mallory.pub.txt")" > "$TMP/bob/contacts.txt"
run_client alice bob 10 6 "mensaje-que-no-debe-llegar"; A=$!
sleep 1
run_client bob alice 8 5 ""; B=$!
wait $A $B
has "$TMP/bob.log" "Firma de 'alice' INVÁLIDA"                 && ok "Bob detecta la firma inválida (posible MITM)" || bad "Bob no detectó la suplantación"
has "$TMP/bob.log" "Canal cifrado E2E establecido" && bad "Bob estableció un canal con un impostor" || ok "Bob NO establece canal con el impostor"
has "$TMP/bob.log" "mensaje-que-no-debe-llegar"    && bad "Se entregó un mensaje de un peer no autenticado" || ok "No se entrega ningún mensaje del peer no autenticado"

echo "== 5. Contacto sin pinear: el cliente se niega a continuar =="
rm -f "$TMP/bob/contacts.txt"
( cd "$TMP/bob" && timeout 5 "$ROOT/client" bob alice 127.0.0.1 "$PORT" </dev/null >"$TMP/bob2.log" 2>&1 ); RC=$?
[ "$RC" -eq 1 ] && has "$TMP/bob2.log" "contacts.txt" && ok "Sin clave pineada el cliente aborta con instrucciones" || bad "El cliente no abortó (código $RC)"

echo "== 6. Nombres de usuario peligrosos (path traversal) =="
( cd "$TMP/bob" && timeout 5 "$ROOT/client" "../evil" alice 127.0.0.1 "$PORT" </dev/null >"$TMP/bob3.log" 2>&1 ); RC=$?
[ "$RC" -ne 0 ] && [ ! -e "$TMP/evil.identity" ] && ok "Se rechaza '../evil' y no se crea ningún fichero fuera del directorio" || bad "Nombre de usuario peligroso aceptado"

echo
echo "Resultado: $PASS correctas, $FAIL fallidas"
[ "$FAIL" -eq 0 ]
