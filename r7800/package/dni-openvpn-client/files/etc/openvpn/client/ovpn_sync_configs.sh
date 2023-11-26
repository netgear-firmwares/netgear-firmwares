#!/bin/sh

[ "$OVPN_CLIENT_TRACE" = "on" ] && set -x

. /etc/openvpn/openvpn_client.env

[ ! -d ${ovpn_client_data_dir} ] && mkdir -p ${ovpn_client_data_dir}
trap 'echo "$update_interval_t" > $ovpn_client_update_time && exit 0' SIGTERM

CONFIG="/bin/config"
product="$(awk '{print tolower($0)}' /module_name)"
if [ "x`/bin/config get vpn_client_ovpn_cfg_env`" = "xqa" ]; then
	remote_location="https://http.fw.updates1.netgear.com/sw-apps/vpn-client/${product:-r7800}/SQA"
else
	remote_location="https://http.fw.updates1.netgear.com/sw-apps/vpn-client/${product:-r7800}"
fi
vpn_country=`$CONFIG get vpn_client_ovpn_cfg_country`
vpn_city=`$CONFIG get vpn_client_ovpn_cfg_city`
vpn_protocol=`$CONFIG get vpn_client_ovpn_cfg_protocol`
vpn_provider=`$CONFIG get vpn_client_ovpn_cfg_provider`
vpn_client_ovpn_cfg_update_interval=`/bin/config get vpn_client_ovpn_cfg_update_interval`
if [ "$vpn_client_ovpn_cfg_update_interval" -gt 0 ] 2>/dev/null ;then
	update_interval=$vpn_client_ovpn_cfg_update_interval
else
	update_interval=86400
fi

if [ -f $ovpn_client_update_time ]; then
	update_interval_t=`cat $ovpn_client_update_time`
	[ $update_interval_t -gt 0 ] || update_interval_t=$update_interval
else
	update_interval_t=$update_interval
fi
id_file="updated_date.txt"

curl_opt="-s --capath /etc/ssl/certs --retry 5"

init_local_dirs()
{
	mkdir -p ${ovpn_client_cfg_dir}/${purevpn}
	mkdir -p ${ovpn_client_cfg_dir}/${hidemyass}
}

download_and_expand_configs()
{
	if [ "x$1" = "xHideMyAss" ]; then
		provider_dir="hma" && gap='.'
	else
		provider_dir=`echo $1 |tr '[A-Z]' '[a-z]'` && gap='-'
	fi
	provider_local=`echo $1 | tr '[A-Z]' '[a-z]'`
	#rm -rf ${ovpn_client_cfg_dir}/${purevpn}/* && rm -rf ${ovpn_client_cfg_dir}/${hidemyass}/*
	if [ "x`$CONFIG get vpn_client_ovpn_cfg_city`" = "xAny City" ]; then
		/etc/openvpn/client/citylist
		for city in `cat /tmp/openvpn_anycity`
		do
			if [ ! -f ${ovpn_client_cfg_dir}/$provider_local/$2$gap$city$gap$vpn_protocol.ovpn ]; then
			curl ${curl_opt}\
			$remote_location/$provider_dir/$vpn_protocol/$2$gap$city$gap$vpn_protocol.ovpn\
			-o ${ovpn_client_cfg_dir}/$provider_local/$2$gap$city$gap$vpn_protocol.ovpn
			fi
		done
	else
		if [ ! -f ${ovpn_client_cfg_dir}/$provider_local/$2$gap$vpn_city$gap$vpn_protocol.ovpn ]; then 
		curl ${curl_opt}\
			$remote_location/$provider_dir/$vpn_protocol/$2$gap$vpn_city$gap$vpn_protocol.ovpn\
			-o ${ovpn_client_cfg_dir}/$provider_local/$2$gap$vpn_city$gap$vpn_protocol.ovpn
		fi
	fi
}

update_local_configuration_file(){
	local provider=${1:-purevpn}
	local_files=`ls "${ovpn_client_cfg_dir}/$provider"`
	local config_file
	local country_t city_t proto_t
	for config_file in $local_files
	do
		country_t=`echo $config_file |awk -F '-' '{print $1}'`
		city_t=`echo $config_file |awk -F '-' '{print $2}'`
		proto_t=`echo $config_file |awk -F '-' '{print $3}'|awk -F '.' '{print $1}'`

		curl ${curl_opt}\
			$remote_location/$provider/$proto_t/$config_file\
			-o ${ovpn_client_cfg_dir}/$provider/$config_file
	done
}

if [ -f ${ovpn_client_cfg_dir}/${providerlist_file_name} ]; then
	mv ${ovpn_client_cfg_dir}/${providerlist_file_name} ${ovpn_client_cfg_dir}/${providerlist_file_name}.bak
fi
init_local_dirs
while true; do
	if [ -f ${ovpn_client_cfg_dir}/${providerlist_file_name}.bak ]; then
		mv ${ovpn_client_cfg_dir}/${providerlist_file_name}.bak ${ovpn_client_cfg_dir}/${providerlist_file_name}.new
	else
		curl ${curl_opt} ${remote_location}/providerlist20180914.json -o ${ovpn_client_cfg_dir}/${providerlist_file_name}.new
	fi
	[ -f ${ovpn_client_cfg_dir}/${providerlist_file_name}.new ] && sed -i 's/PureVPN /PureVPN/g' ${ovpn_client_cfg_dir}/${providerlist_file_name}.new 
	if [ ! -f ${ovpn_client_cfg_dir}/${providerlist_file_name} ] \
		|| ! diff ${ovpn_client_cfg_dir}/${providerlist_file_name}.new ${ovpn_client_cfg_dir}/${providerlist_file_name}; then
		mv ${ovpn_client_cfg_dir}/${providerlist_file_name}.new ${ovpn_client_cfg_dir}/${providerlist_file_name}
		if [ "x${vpn_country}" != "x" ] && [ "x${vpn_protocol}" != "x" ] && [ "x${vpn_provider}" != "x" ] ;then
			download_and_expand_configs "${vpn_provider}" "${vpn_country}" "${vpn_city}" "${vpn_protocol}"
		fi
	fi
	
	if [ -f ${ovpn_client_cfg_dir}/${providerlist_file_name} ]; then
		while [ $update_interval_t -gt 0 ]
		do
			sleep 1
			update_interval_t=$(($update_interval_t - 1))
		done
		update_local_configuration_file
		update_interval_t=$update_interval
	else
		sleep 10
	fi
done
