#!/bin/bash
# Build an image from a mod_rpaf source tree and capture the whole behaviour
# matrix under every relevant RPAF_* configuration.
#
#   usage: capture.sh <src-dir> <outdir> [--with-forwarded] [base-image]
#
# <src-dir> is a mod_rpaf working tree (or export). The result is one file per
# configuration in <outdir>, suitable for `diff -ru baseline/ modified/`.
# Pass --with-forwarded only for a tree that knows RPAF_EnableForwarded; an
# older module aborts at config parse time on the unknown directive.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="${1:?source tree}"
OUT="${2:?output dir}"
shift 2
WITH_FORWARDED=no
if [ "${1:-}" = --with-forwarded ]; then
  WITH_FORWARDED=yes
  shift
fi
BASE="${1:-debian:bookworm}"
TAG="rpaf-capture:$(basename "${OUT}")"

rm -rf "${HERE}/src"
mkdir -p "${HERE}/src"
# the build context only needs what compiles the module. Excluding test/ matters
# when SRC is the repository itself, since the copy target lives inside it.
tar -C "${SRC}" --exclude=.git --exclude=./test -cf - . | tar -C "${HERE}/src" -xf -

mkdir -p "${OUT}"
podman build --build-arg "BASE=${BASE}" -t "${TAG}" "${HERE}" >"${OUT}/build.log" 2>&1

run_case() {
  local name="$1"; shift
  echo "  ${name}" >&2
  podman run --rm "${TAG}" "$@" >"${OUT}/${name}.txt" 2>&1
}

echo "capturing into ${OUT}" >&2
run_case trusted
run_case untrusted                         UNTRUSTED
run_case trusted-clean                     CLEANHEADERS
run_case untrusted-clean                   UNTRUSTED CLEANHEADERS
run_case untrusted-forbid                  UNTRUSTED FORBID
if [ "${WITH_FORWARDED}" = yes ]; then
  run_case trusted-forwarded               FORWARDED
  run_case untrusted-forwarded             UNTRUSTED FORWARDED
  run_case trusted-forwarded-clean         FORWARDED CLEANHEADERS
  run_case untrusted-forwarded-clean       UNTRUSTED FORWARDED CLEANHEADERS
  # the minority of our servers that terminate TLS themselves and therefore
  # actually load mod_ssl
  run_case trusted-forwarded-ssl           FORWARDED SSLVHOST
  run_case untrusted-forwarded-ssl         UNTRUSTED FORWARDED SSLVHOST
fi
echo "done" >&2
