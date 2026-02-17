#!/bin/sh
while [ $# -gt 0 ]; do
  if [ "$1" = "-oX" ]; then
    shift
    rm -f "$1"
  fi
  shift
done
exit 0
