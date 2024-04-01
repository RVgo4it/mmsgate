#!/bin/bash

echo
echo $(date -Ins) - Init started!

# maybe mariadb?
if [ -e /usr/bin/mysqld_safe ] ; then
  echo $(date -Ins) - Starting MariaDB
  sudo mysqld_safe &
  sleep 10
fi

# keep refreshing permissions for mmsgate to talk to flexisip
{ while [ true ] ; do
  sleep 60
  sudo chmod 0775 /tmp/flexisip-proxy-* 2>/dev/null
  sudo chown root:mmsgate /tmp/flexisip-proxy-* 2>/dev/null
done; } &

if [ "$1" == "--mmsgatedebug" ] ; then MMSGATEDEBUG=--mmsgate-logger=DEBUG; fi
{ while [ true ] ; do
  echo $(date -Ins) - "Starting MMSGate"
  sudo su -c "/home/mmsgate/script/mmsgate.py $MMSGATEDEBUG" mmsgate
  echo $(date -Ins) - "MMSGate ended...  waiting 60 seconds."
  sleep 60
done; } &

# the primary process
if [ "$1" == "--flexisipdebug" ] ; then FLEXISIPDEBUG=-d; fi
while [ true ] ; do
  echo $(date -Ins) - "Starting Flexisip"
  sudo /opt/belledonne-communications/bin/flexisip --server proxy --syslog --pidfile /var/run/flexisip-proxy.pid $FLEXISIPDEBUG
  echo $(date -Ins) - "Flexisip ended...  waiting 60 seconds."
  sleep 60
done; 

