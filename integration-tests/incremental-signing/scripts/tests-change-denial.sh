#!/bin/sh
set -e
export LC_ALL=C
CASCADE="cargo run --bin cascade"
KEY=$PWD/keys/Kexample.+015+02835.key
for zonemd in '' # zmd384
do
	for m in nsec3/nsec nsec3-opt-out/nsec nsec/nsec3 nsec3-opt-out/nsec3 nsec/nsec3-opt-out nsec3/nsec3-opt-out
	do
		case $m in
		nsec/*)
			denial_before=nsec
		;;
		nsec3/*)
			denial_before=nsec3
		;;
		nsec3-opt-out/*)
			denial_before=nsec3-opt-out
		;;
		esac

		case $m in
		*/nsec)
			denial_after=nsec
		;;
		*/nsec3)
			denial_after=nsec3
		;;
		*/nsec3-opt-out)
			denial_after=nsec3-opt-out
		;;
		esac

		case "$zonemd" in
		'')
			policy="$m"
		;;
		zmd384)
			policy="$m-$zonemd"
		;;
		esac

		for test in 1 2 3
		do
			echo test $test denial $m $zonemd
			cp zones/incremental-signing-test${test}-input1.zone example.in
			cp policies/$denial_before.toml policies/work.toml
			$CASCADE policy reload
			$CASCADE zone add --source $PWD/example.in --policy work example --import-csk-file $KEY

			# Wait for first version to be signed.
			for i in 1 2 3 4 5 6 7 8 9 10
			do
			    dig @127.0.0.1 -p 8053 example soa |
				grep 12345  && break
			    echo first version is not signed yet, sleeping
			    sleep 1
			done
			dig @127.0.0.1 -p 8053 example soa |
			    grep 12345 ||
				{
				    echo first version is not signed yet, giving up
				    exit 1
				}
			cp zones/incremental-signing-test${test}-input2.zone example.in
			cp policies/$denial_after.toml policies/work.toml
			$CASCADE policy reload

			$CASCADE zone reload example
			for i in 1 2 3 4 5 6 7 8 9 10
			do
			    dig @127.0.0.1 -p 8053 example soa |
				grep 23456  && break
			    echo second version is not signed yet, sleeping
			    sleep 1
			done
			dig @127.0.0.1 -p 8053 example soa |
			    grep 23456 ||
				{
				    echo second version is not signed yet, giving up
				    exit 1
				}

			cp reference-output/incremental-signing-test${test}-input2.zone.${denial_after}.signed.sorted reference.output.sorted
			dig @127.0.0.1 -p 8053 example axfr |
			    egrep -v '^;|^$' | sort -u > output.sorted
			diff -w -u output.sorted reference.output.sorted
			$CASCADE zone remove example
		done
	done
done
