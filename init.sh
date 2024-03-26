#!/bin/bash

echo
echo $(date -Ins) - Init started!

# keep refreshing permissions for mmsgate to talk to flexisip
{ while [ true ] ; do
  sleep 60
  sudo chmod 0775 /tmp/flexisip-proxy-*
  sudo chown root:mmsgate /tmp/flexisip-proxy-*
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

