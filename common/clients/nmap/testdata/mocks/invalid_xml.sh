#!/bin/sh
while [ $# -gt 0 ]; do
  if [ "$1" = "-oX" ]; then
    shift
    echo 'invalid xml' > "$1"
  fi
  shift
done
exit 0
