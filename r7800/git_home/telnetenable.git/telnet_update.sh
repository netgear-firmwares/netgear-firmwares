#!/bin/sh

#Purpose:
#update telnet related parameters from config database

CONFIG=/bin/config

PASSWORD_FILE="/tmp/uhttp_key_telnet"
LANGUAGE_FILE="/tmp/gui_language_telnet"

echo -n "`$CONFIG get http_passwd`" >$PASSWORD_FILE
echo -n "`$CONFIG get GUI_Region`" >$LANGUAGE_FILE





