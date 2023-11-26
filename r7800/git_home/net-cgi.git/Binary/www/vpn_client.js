function valid_add()
{   
	if(array_num==5)  
	{
		alert("Maximum to support 5 devices");
		return false;
	}

	location.href="vpn_client_add_wait.htm";
}

function check_vpn_client_add(cf,flag)
{
	if( array_num == 5 && flag== 'add')
	{
		alert("Maximum to support 5 devices");
		return false;
	}

	if(cf.dv_name.value == "")
	{
		alert("$device_name_null");
		return false;
	}
	if(cf.dv_name.value.length > 20)
	{
		alert("$device_name_error");
		return false;
	}
	for(i=0;i<cf.dv_name.value.length;i++)
	{ 
		if(isValidChar(cf.dv_name.value.charCodeAt(i))==false)
		{
			alert("$device_name_error");
			return false;
		}
	}

	if(cf.rsv_mac.value.length==12 && cf.rsv_mac.value.indexOf(":")==-1)
	{
		var mac=cf.rsv_mac.value; 
		cf.rsv_mac.value=mac.substr(0,2)+":"+mac.substr(2,2)+":"+mac.substr(4,2)+":"+mac.substr(6,2)+":"+mac.substr(8,2)+":"+mac.substr(10,2);
	}
	else if ( cf.rsv_mac.value.split("-").length == 6 )
	{
		var tmp_mac = cf.rsv_mac.value.replace(/-/g,":");
		cf.rsv_mac.value=tmp_mac;
	}	
	if(maccheck(cf.rsv_mac.value) == false)
		return false;
	/*	var start_array=startip.split('.');
	var end_array=endip.split('.');
	var msg_ip="$rsvip_dhcp_rang"+"[ "+startip+" ~ "+endip+" ].";

	if(!(parseInt(start_array[3]) <= parseInt(cf.rsv_ip4.value,10) && parseInt(cf.rsv_ip4.value,10) <= parseInt(end_array[3]) && start_array[2] == parseInt(cf.rsv_ip3.value,10) && start_array[1] == parseInt(cf.rsv_ip2.value,10) && start_array[0] == parseInt(cf.rsv_ip1.value,10)))
	{
		alert(msg_ip);
		return false;
	}
*/
	for(i=1;i<=array_num;i++)
	{
		var str = eval ( 'vpn_selected_client' + i ).replace(/&#92;/g, "\\").replace(/&lt;/g,"<").replace(/&gt;/g,">").replace(/&#40;/g,"(").replace(/&#41;/g,")").replace(/&#34;/g,'\"').replace(/&#39;/g,"'").replace(/&#35;/g,"#").replace(/&#38;/g,"&");
		var each_info=str.split(' ');
		if(flag == 'edit')
		{
			if(select_editnum!=i)
			{
				if( cf.rsv_mac.value.toLowerCase() == each_info[0].toLowerCase())
				{
					alert("This device has been added!");
					return false;
				}
			}
		}
		else
		{
			if( cf.rsv_mac.value.toLowerCase() == each_info[0].toLowerCase())
			{
				alert("This device has been added!");
				return false;
			}	
		}
	}

	if(typeof(apply_flag) != "undefined")
		apply_flag = 1;

	cf.submit();

	return true;
}
function check_vpn_client_del(cf)
{
	if(array_num == 0)
	{
		alert("$port_del");
		return false;
	}
	var count_select=0;
	var select_num;
	if( array_num == 1)
	{
		if(cf.ruleSelect.checked == true)
		{
			count_select++;
			select_num=1;
		}
	}
	else for(i=0;i<array_num;i++)
		if(cf.ruleSelect[i].checked == true)
		{
			count_select++;
			select_num=i+1;
		}
	if(count_select==0)
	{
		alert("$port_del");
		return false;
	}
	else
	{
		cf.select_del.value=select_num;
		cf.submit_flag.value="vpn_client_del";
		cf.submit();
		return true;
	}	
}

function check_vpn_client_editnum(cf)
{
	if (array_num == 0)
	{
		alert("$port_edit");
		return false;
	}
	var count_select=0;
	var select_num;
	if( array_num == 1)
	{
		if(cf.ruleSelect.checked == true)
		{
			count_select++;
			select_num=1;
		}
	}
	else for(i=0;i<array_num;i++)
		if(cf.ruleSelect[i].checked == true)
		{
			count_select++;
			select_num=i+1;
		}
	if(count_select==0 || count_select!=1)
	{
		alert("$port_edit");
		return false;
	}
	else
	{
		cf.select_edit.value=select_num;
		cf.submit_flag.value="vpn_client_editnum";
		cf.action="/apply.cgi?/vpn_client_edit.htm timestamp="+ts;
		cf.submit();//add
		return true;
	}	
}

function data_select(num)
{
	var cf=document.forms[0];
	if( show_name_array[num] == "<unknown>" || show_name_array[num] == "&lt;unknown&gt;" )
		cf.dv_name.value='<$unknown_mark>';
	else
		cf.dv_name.value=show_name_array[num].replace(/&lt;/g,"<").replace(/&gt;/g,">");

	if( show_mac_array[num] == "<unknown>" ||  show_mac_array[num] =="&lt;unknown&gt;" )
		cf.rsv_mac.value="";
	else
		cf.rsv_mac.value=show_mac_array[num];

	if( show_ip_array[num] != "----" )
	{
		var ip_array=show_ip_array[num].split('.');
		cf.rsv_ip1.value=ip_array[0];
		cf.rsv_ip2.value=ip_array[1];
		cf.rsv_ip3.value=ip_array[2];
		cf.rsv_ip4.value=ip_array[3];	
	}
}

function check_vpn_selected_client(cf)
{
	if(cf.selected_device[0].checked == true)
	{
		cf.selected_mode.value = "0";

	}else{
		if(array_num == 0)
		{
			alert("Please select at least one device!");
			return false;
		}
		/*var count_select=0;
		var select_num=new Array();
		if( array_num == 1)
		{
			if(cf.ruleSelect.checked == true)
			{
				count_select++;
				select_num[0]=1;
			}
		}
		else{
			for(i=0;i<array_num;i++){
				if(cf.ruleSelect[i].checked == true)
				{
					select_num[count_select]=i+1;
					count_select++;
				}
			}
		}
		if(count_select==0)
		{
			alert("Please select at least one device!");
			return false;
		}
		else
		{*/
			var select_value="";
			for(i=0;i<array_num;i++){
				
				select_value=select_value+(i+1)+" ";
			}
			cf.select_num_list.value=select_value;
			cf.selected_mode.value = "1";
		//}
	}
	cf.submit_flag.value="vpn_client_selected";
	cf.submit();
	return true;
}

function clickUpgrade(form)
{
	if(form.mtenFWUpload.value=="")
	{
		alert("$in_upgrade");
		return false;
	}
	/*var filestr=form.mtenFWUpload.value;
	var file_format=filestr.substr(filestr.lastIndexOf(".")+1); 
	if(file_format.toUpperCase()!="IMG")
	{
		alert("$not_correct_file"+"img");
		return false;
	}*/
	form.hidden_enable_vpn.disabled = true;
	form.vpn_country_text.disabled = true;
	form.vpn_country.disabled=true;
	form.user.disabled = true;
	form.password.disabled =true;
	form.vpn_server.disabled=true;
	form.vpn_protocol.disabled=true;
	form.vpn_city.disabled=true;
	form.submit_flag.disabled=true;
	form.hidden_pwd_change.disabled=true;
	form.hidden_pwd.disabled=true;
	form.enable_vpn.disabled=true;
	form.enable_auth.disabled=true;
	form.hidden_enable_auth.disabled=true;
	form.action="/vpncfg_upload.cgi?/vpn_client_enhance.htm timestamp="+ts;
	form.enctype="multipart/form-data";
	form.submit();	
}

