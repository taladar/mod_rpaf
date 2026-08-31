#!/bin/bash
# Runs the mod_rpaf behaviour matrix inside the container and prints a
# deterministic, normalised transcript on stdout. Every apache -D flag given as
# an argument is passed through, so the caller selects trusted/untrusted and the
# optional RPAF_* variants.
set -u

DEFINES=()
for d in "$@"; do
  DEFINES+=(-D "$d")
done

set +u
# shellcheck disable=SC1091 # provided by the apache2 package inside the container
. /etc/apache2/envvars
set -u
mkdir -p "${APACHE_RUN_DIR}" "${APACHE_LOCK_DIR}" "${APACHE_LOG_DIR}"
rm -f "${APACHE_PID_FILE}"
apache2 -DFOREGROUND "${DEFINES[@]}" >/tmp/apache.out 2>/tmp/apache.err &
APACHE_PID=$!

ready=no
for _ in $(seq 1 100); do
  # any HTTP status means apache is up; RPAF_ForbidIfNotProxy legitimately answers 403
  if [ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 -H 'Host: test.example' http://127.0.0.1/cgi-bin/env.sh)" != 000 ]; then
    ready=yes
    break
  fi
  sleep 0.2
done
if [ "${ready}" != yes ]; then
  echo "FATAL: apache did not become ready" >&2
  cat /tmp/apache.err >&2
  tail -30 /var/log/apache2/error.log >&2 2>/dev/null
  exit 1
fi

BASE=http://127.0.0.1/cgi-bin/env.sh
HOST='Host: test.example'

norm() {
  # request ids embed the connection id and a timestamp
  sed -e 's/apache-[0-9]\+-[0-9]\+/apache-<GENERATED>/g'
}

run() {
  local name="$1"; shift
  echo "===== ${name} ====="
  curl -s -H "${HOST}" "$@" | norm
  echo
}

echo "##### defines: ${*:-none} #####"
echo

run "01 plain"                        "${BASE}"
run "02 xff ipv4"                     -H 'X-Forwarded-For: 1.2.3.4' "${BASE}"
run "03 xff chain"                    -H 'X-Forwarded-For: 1.2.3.4, 127.0.0.1' "${BASE}"
run "04 xff ipv6"                     -H 'X-Forwarded-For: 2001:db8::1' "${BASE}"
run "05 xf-host"                      -H 'X-Forwarded-For: 1.2.3.4' -H 'X-Forwarded-Host: other.example' "${BASE}"
run "06a xf-proto https"              -H 'X-Forwarded-For: 1.2.3.4' -H 'X-Forwarded-Proto: https' "${BASE}"
run "06b xf-https on"                 -H 'X-Forwarded-For: 1.2.3.4' -H 'X-Forwarded-HTTPS: on' "${BASE}"
run "06c xf-protocol https"           -H 'X-Forwarded-For: 1.2.3.4' -H 'X-Forwarded-Protocol: https' "${BASE}"
run "07 xf-port"                      -H 'X-Forwarded-For: 1.2.3.4' -H 'X-Forwarded-Port: 443' "${BASE}"
run "08 request id injected"          -H 'X-Forwarded-For: 1.2.3.4' -H 'X-Request-Id: injected-by-client' "${BASE}"
run "10 rewritten uri"                -H 'X-Forwarded-For: 1.2.3.4' -H 'X-Forwarded-Proto: https' http://127.0.0.1/rewritten/foo
run "11 forwarded header"             -H 'Forwarded: for=1.2.3.4;proto=https;host=evil.example' "${BASE}"
run "11b forwarded + xff"             -H 'X-Forwarded-For: 1.2.3.4' -H 'Forwarded: for=9.9.9.9;proto=https;host=evil.example' "${BASE}"
run "12 xf-user"                      -H 'X-Forwarded-For: 1.2.3.4' -H 'X-Forwarded-User: root' -H 'X-Forwarded-Email: root@evil.example' "${BASE}"
run "13 x-real-ip / xf-server / ssl"  -H 'X-Forwarded-For: 1.2.3.4' -H 'X-Real-IP: 9.9.9.9' -H 'X-Forwarded-Server: evil.example' -H 'X-Forwarded-Ssl: on' "${BASE}"
run "14 x-host / x-https / x-port"    -H 'X-Forwarded-For: 1.2.3.4' -H 'X-Host: other.example' -H 'X-HTTPS: on' -H 'X-Port: 8443' "${BASE}"

case " $* " in
  *" SSLVHOST "*)
    # TLS terminated by this server rather than by a proxy in front of it. At
    # post_read_request neither the rpaf_https connection note nor mod_ssl's
    # HTTPS environment variable exists yet (mod_ssl sets that in its fixup
    # hook), so proto=https here can only come from the ssl_is_https optional
    # function, which is what these two cases are here to pin down.
    echo "===== 18 direct https, no X-Forwarded-* at all ====="
    curl -sk -H "${HOST}" https://127.0.0.1/cgi-bin/env.sh | norm
    echo

    echo "===== 19 direct https with an upstream style proto header ====="
    curl -sk -H "${HOST}" -H 'X-Forwarded-For: 1.2.3.4' -H 'X-Forwarded-Proto: http' https://127.0.0.1/cgi-bin/env.sh | norm
    echo
    ;;
esac

echo "===== 16 ipv6 peer (node identifier quoting) ====="
curl -s -g -H "${HOST}" 'http://[::1]/cgi-bin/env.sh' | norm
echo

echo "===== 17 host header with a quote and a port ====="
curl -s -H 'Host: te"st.example:8080' "${BASE}" | norm
echo

echo "===== 09 keep-alive, two requests on one connection ====="
curl -s -H "${HOST}" -H 'X-Forwarded-For: 1.2.3.4' "${BASE}" \
     --next -s -H "${HOST}" -H 'X-Forwarded-For: 5.6.7.8' "${BASE}" | norm
echo

echo "===== 15 status codes ====="
for case_name in plain xff; do
  if [ "${case_name}" = plain ]; then
    code=$(curl -s -o /dev/null -w '%{http_code}' -H "${HOST}" "${BASE}")
  else
    code=$(curl -s -o /dev/null -w '%{http_code}' -H "${HOST}" -H 'X-Forwarded-For: 1.2.3.4' "${BASE}")
  fi
  echo "${case_name}=${code}"
done
echo

echo "===== apache error log (rpaf/config lines) ====="
grep -iE 'rpaf|segmentation|core dump' /var/log/apache2/error.log /tmp/apache.err 2>/dev/null | sed -e 's/^\[[^]]*\] //' || true
echo

kill "${APACHE_PID}" 2>/dev/null
wait "${APACHE_PID}" 2>/dev/null
exit 0
