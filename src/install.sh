#!/bin/sh
#
# src/install.sh
# This script is part of the IPTraf installation system.  Do not attempt
# to run this directly from the command prompt.
#
# Version 3.0.0 Copyright (c) Gerard Paul Java 2002
#

if [ "$1" = "" ]; then
    echo "This script is part of the IPTraf installation system, and"
    echo "should not be run by itself."
    exit 1
fi

INSTALL=/usr/bin/install
TARGET=$1
WORKDIR=$2
LOGDIR=$3
LOCKDIR=$4

echo
echo "*** Installing executable programs and preparing work directories"
echo
echo ">>> Installing iptraf in $TARGET"
$INSTALL -m 0700 -o root -g root -s iptraf $TARGET
echo ">>> Installing rvnamed in $TARGET"
$INSTALL -m 0700 -o root -g root -s rvnamed $TARGET

if [ ! -d $WORKDIR ]; then
    echo ">>> Creating IPTraf work directory $WORKDIR"
else
    echo ">>> IPTraf work directory $WORKDIR already exists"
    rm -f $WORKDIR/othfilter.dat
fi

$INSTALL -m 0700 -o root -g root -d $WORKDIR

if [ ! -d $LOGDIR ]; then
    echo ">>> Creating IPTraf log directory $LOGDIR"
else
    echo ">>> IPTraf log directory $LOGDIR already exists"
fi
$INSTALL -m 0700 -o root -g root -d $LOGDIR

if [ ! -d $LOCKDIR ]; then
    echo ">>> Creating IPTraf lockfile directory $LOCKDIR"
else
    echo ">>> IPTraf lockfile directory $LOCKDIR already exists"
fi
$INSTALL -m 0700 -o root -g root -d $LOCKDIR
echo
echo
echo "*** iptraf, and rvnamed executables are in $TARGET"
echo "*** Log files are placed in $LOGDIR"

################# Filter clearing for 3.0 ##########################

if [ ! -f $WORKDIR/version ]; then
    echo ">>> Clearing old filter list"
    if [ -f $WORKDIR/tcpfilters.dat ]; then
        mv -f $WORKDIR/tcpfilters.dat $WORKDIR/tcpfilters.dat~
    fi
    
    if [ -f $WORKDIR/udpfilters.dat ]; then
        mv -f $WORKDIR/udpfilters.dat $WORKDIR/udpfilters.dat~
    fi

    if [ -f $WORKDIR/othipfilters.dat ]; then
        mv -f $WORKDIR/othipfilters.dat $WORKDIR/othipfilters.dat~
    fi

    rm -f $WORKDIR/savedfilters.dat
fi
####################################################################

cat version > $WORKDIR/version

echo 
echo

echo "======================================================================"
echo
echo "Please read the RELEASE-NOTES file for important new information about"
echo "this version. You can view this file now (will require the 'less'"
echo "program in /usr/bin.  Press Q to quit when done)."
echo
echo -n "Would you like to view the RELEASE-NOTES file now (Y/N)? "; read YESNO

if [ "$YESNO" = "y" -o "$YESNO" = "Y" ]; then
    less ../RELEASE-NOTES
fi

clear
echo
echo "====================================================================="
echo
echo "Thank you for installing IPTraf.  You can now start IPTraf by issuing"
echo "the command"
echo
echo "    $TARGET/iptraf"
echo
echo "at your shell prompt.  You can also add $TARGET to your PATH environment"
echo "variable to avoid having to type the pathname when invoking the program."
echo

exit 0

