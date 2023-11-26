#!/bin/sh

router_region=`artmtd -r region |grep REGION|awk -F ': ' '{print $2}'`
if [ "x$router_region" = "xPR" ]; then
	exit 0
fi

case $1 in
	'apply')
		killall ovpn_sync_configs.sh
		#Sleep 1 second to let script handle the SIGTERM signal
		sleep 1
		/etc/openvpn/client/ovpn_sync_configs.sh &
		/usr/bin/openvpn_client.sh reconnect &
		;;
	'reconnect')
		sleep 2
		/usr/bin/openvpn_client.sh reconnect
		;;
esac

