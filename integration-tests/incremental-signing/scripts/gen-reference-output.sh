#!/bin/sh
INCEPTION=1600000000
EXPIRATION=1700000000
for zonemd in '' 'zmd384'
do
	case "$zonemd" in
	'')
		zonemd_params=""
		zonemd_output_name=""
	;;
	zmd384)
		zonemd_params="-z SHA384"
		zonemd_output_name=".zmd384"
	;;
	esac
	for m in nsec nsec3 nsec3-opt-out
	do
		case "$m" in
		nsec)
			params=""
		;;
		nsec3)
			params="-n"
		;;
		nsec3-opt-out)
			params="-n -P"
		;;
		esac
		for z in zones/*input[23].zone
		do
			echo $z
			echo $zonemd $zonemd_params $zonemd_output_name
			dnst signzone -T -o example -f - -e $EXPIRATION -i $INCEPTION $params $zonemd_params $z keys/Kexample.+015+02835 |
				sort -u > reference-output/$(basename $z).${m}${zonemd_output_name}.signed.sorted
		done
	done
done
