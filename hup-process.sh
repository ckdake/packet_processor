#!/bin/bash
# hup-process.sh

NOPROCESS=2

process=zcc_configd

t=`/sbin/pidof $process`

if [ -z "$t" ]
then
  echo "Process $process was not running."
  echo "Nothing killed."
  exit $NOPROCESS
fi  

kill -s SIGHUP $t

exit 0
