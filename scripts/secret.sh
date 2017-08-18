ASTERISKDIR=/etc/asterisk

restore_secret()
{
	local section_found
	local secret
	local config_file
	# Provide backwards compatibility
	if [ -f "$ASTERISKDIR/sip_providers.conf" ] ; then
		config_file=$ASTERISKDIR/sip_providers.conf
	elif [ -f "$ASTERISKDIR/sip_peers.conf" ] ; then
		config_file=$ASTERISKDIR/sip_peers.conf
	else
		return
	fi

	if [ -f $config_file ] ; then
		while read line
		do
			if [ -n "$section_found" ] ; then
				if [ ! "${line##secret*}" ] ; then
					#we found the secret
					secret=$(echo "$line" | sed 's/secret[ \t]*= *//g' | sed 's/[ \t;].*//g')
					echo "$secret"
					return
				fi
			elif [ "$line" = "[$1]" ] ; then
				#we found the correct section
				section_found=1
			fi
		done < $config_file
	fi
}

secret=$(restore_secret $1)
echo -n "$secret"
