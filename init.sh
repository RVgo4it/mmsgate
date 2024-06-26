#!/bin/bash
# This is the initial script called by dumb-init

echo
echo $(date -Ins) - Init started!

signal_exit() {
  sleep 10
}

# help pass the SIGTERM to child processes
trap signal_exit SIGTERM

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

# start mmsgate script
if [ "$1" == "--mmsgatedebug" ] ; then MMSGATEDEBUG=--mmsgate-logger=DEBUG; fi
{ while [ true ] ; do
  echo $(date -Ins) - "Starting MMSGate"
  sudo su -c "/home/mmsgate/script/mmsgate.py $MMSGATEDEBUG" mmsgate
  echo $(date -Ins) - "MMSGate ended...  waiting 60 seconds."
  sleep 60
done; } &

# start the primary process, flexisip
if [ "$1" == "--flexisipdebug" ] ; then FLEXISIPDEBUG=-d; fi
while [ true ] ; do
  echo $(date -Ins) - "Starting Flexisip"
  sudo /opt/belledonne-communications/bin/flexisip --server proxy --syslog --pidfile /var/run/flexisip-proxy.pid $FLEXISIPDEBUG
  echo $(date -Ins) - "Flexisip ended...  waiting 60 seconds."
  sleep 60
done; 

