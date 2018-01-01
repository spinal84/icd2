#!/bin/sh

# Copyright (C) 2009 Nokia Corporation. All rights reserved.
# Author: jukka.rissanen@nokia.com

# This script will remove duplicate IAPs from gconf

TAG=`basename $0`
icd_entry=system/osso/connectivity/IAP

# Run gconftool via server or directly if D-Bus is not running
gconftool_run () {
    if gconftool-2 -p &>/dev/null
    then
	gconftool-2 $* 2>/dev/null
    else
	gconftool-2 --direct \
	    --config-source xml::/etc/gconf/gconf.xml.defaults \
	    $* | sed '1 d' 2>/dev/null
    fi
}

# Get the list of IAPs and then check if there are any duplicates found
# (having a same name is considered a duplicate)

COUNT=0
TMP1=/tmp/.$TAG.tmp
rm -f $TMP1
for IAP in `gconftool_run -R /$icd_entry | grep /system | sed 's/:$//'`
do
  NAME=`gconftool_run --get "$IAP/name"`
  # If NAME is not set, then there cannot be any duplicate for that IAP.
  if [ ! -z "$NAME" ]; then
      grep -- "^${NAME}$" $TMP1 > /dev/null 2>&1
      if [ $? -eq 0 ]; then
          # We found a duplicate
	  gconftool_run --recursive-unset "$IAP"
	  COUNT=`expr $COUNT + 1`
	  logger -t "$TAG" "Removed $IAP ($NAME)"
      else
	  echo "$NAME" >> $TMP1
      fi
  fi
done
if [ "$COUNT" -gt 0 ]; then
    logger -t "$TAG" "Restore removed $COUNT duplicate IAP"
fi
rm -f $TMP1

exit 0
