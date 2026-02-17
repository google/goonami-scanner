#!/bin/sh
while [ $# -gt 0 ]; do
  if [ "$1" = "-oX" ]; then
    shift
    echo '<nmaprun args="nmap -p 80 127.0.0.1"><host><status state="up" reason="syn-ack"/></host></nmaprun>' > "$1"
  fi
  shift
done
exit 0
