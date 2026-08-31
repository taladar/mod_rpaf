#!/bin/sh
# Dumps the request-relevant part of the CGI environment. Volatile values are
# normalised by run-tests.sh, not here.
echo "Content-Type: text/plain"
echo
for v in \
  VHOST_ID \
  REMOTE_ADDR \
  SERVER_NAME \
  SERVER_PORT \
  SERVER_ADDR \
  REQUEST_SCHEME \
  HTTPS \
  REMOTE_USER \
  HTTP_HOST \
  X_REQUEST_ID \
  HTTP_X_REQUEST_ID \
  HTTP_FORWARDED \
  HTTP_X_FORWARDED_FOR \
  HTTP_X_FORWARDED_HOST \
  HTTP_X_FORWARDED_SERVER \
  HTTP_X_FORWARDED_PROTO \
  HTTP_X_FORWARDED_PROTOCOL \
  HTTP_X_FORWARDED_HTTPS \
  HTTP_X_FORWARDED_SSL \
  HTTP_X_FORWARDED_PORT \
  HTTP_X_FORWARDED_USER \
  HTTP_X_FORWARDED_EMAIL \
  HTTP_X_FORWARDED_PREFERRED_USERNAME \
  HTTP_X_FORWARDED_GROUPS \
  HTTP_X_REAL_IP \
  HTTP_X_HOST \
  HTTP_X_HTTPS \
  HTTP_X_PORT
do
  eval "val=\${$v+set}"
  if [ "${val:-}" = set ]; then
    eval "val=\$$v"
    echo "$v=$val"
  else
    echo "$v=<unset>"
  fi
done
