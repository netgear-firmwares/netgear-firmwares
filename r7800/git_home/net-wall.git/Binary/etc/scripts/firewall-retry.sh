#! /bin/sh

netwall="/usr/sbin/net-wall"

echo 1 > /tmp/netwall-retrying

[ ! -f "/tmp/netwall-retry" ] && echo 0 > /tmp/netwall-retry

trytime=$(cat /tmp/netwall-retry)

let trytime+=1

[ $trytime -gt 60 ] && echo "exceed to exit" && exit

echo $trytime > /tmp/netwall-retry

waittime=5

sleep $waittime

echo 0 > /tmp/netwall-retrying

$netwall restart

