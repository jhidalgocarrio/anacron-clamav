#!/bin/bash
# written by Tomas Nevar (tomas@lisenet.com)
# 17/01/2014 (dd/mm/yy)
# copyleft free software
#
LOGFILE="/var/log/clamav/clamav-$(date +'%Y-%m-%d').log";
HOST="$(hostname --long)";
EMAIL_MSG="Weekly ClamAV Scan";
DIRTOSCAN="/home/javi/.ssh";
NOTIFY_SEND_BIN="/usr/bin/notify-send"
USER=javi

USER_DBUS_PROCESS_NAME="gconfd-2"
DBUS_PID=`ps ax | grep $USER_DBUS_PROCESS_NAME | grep -v grep | awk '{ print $1 }'`

# get DBUS_SESSION_BUS_ADDRESS variable
DBUS_SESSION=`grep -z DBUS_SESSION_BUS_ADDRESS /proc/$DBUS_PID/environ | sed -e s/DBUS_SESSION_BUS_ADDRESS=//`

# Check for mail installation
type mail >/dev/null 2>&1 || { echo >&2 "I require mail but it's not installed. Aborting."; exit 1; };

# Update ClamAV database
echo "Looking for ClamAV database updates...";
freshclam --quiet;

TODAY=$(date +%u);

DIRSIZE=$(du -sh "$DIRTOSCAN"  2>/dev/null|cut -f1);
echo -e "Starting a weekly scan of "$DIRTOSCAN" directory.\nAmount of data to be scanned is "$DIRSIZE".";
clamscan -ri "$DIRTOSCAN" &>"$LOGFILE";

# get the value of "Infected lines"
MALWARE=$(tail "$LOGFILE"|grep Infected|cut -d" " -f3);

# if the value is not equal to zero, send an email with the log file attached
if [ "$MALWARE" -ne "0"  ]; then
    DBUS_SESSION_BUS_ADDRESS=$DBUS_SESSION su -c "$NOTIFY_SEND_BIN \"$EMAIL_MSG Malware Found\" \"Please see the log file at $LOGFILE\"" $USER
else
    DBUS_SESSION_BUS_ADDRESS=$DBUS_SESSION su -c "$NOTIFY_SEND_BIN \"$EMAIL_MSG is clean\" \"Further details at $LOGFILE\"" $USER
fi

echo "The script has finished.";
exit 0;
