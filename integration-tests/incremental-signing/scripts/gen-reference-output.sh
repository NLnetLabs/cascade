#!/bin/sh
INCEPTION=1600000000
EXPIRATION=1700000000
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
		dnst signzone -T -o example -f - -e $EXPIRATION -i $INCEPTION $params $z keys/Kexample.+015+02835 |
			sort -u > reference-output/$(basename $z).$m.signed.sorted
	done
done
