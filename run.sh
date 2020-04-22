#!/bin/sh
echo "Log: http-proxy.log"
if nohup echo 1 >/dev/null 2>&1; then
  (nohup ./http-proxy -p 8080 > http-proxy.log 2>&1 &)
else
  (./http-proxy -p 8080 > http-proxy.log 2>&1 &)
fi
