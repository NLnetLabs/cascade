#!/bin/sh
set -e
export LC_ALL=C
CASCADE="cargo run --bin cascade"
KEY=$PWD/keys/Kexample.+015+02835.key

for test in 1 2
do
	cp zones/test${test}.zone example.in
	$CASCADE zone add --source $PWD/example.in --policy review-test example --import-csk-file $KEY

	serial="$test$test$test$test$test"

	# Wait for the zone to be signed.
	for i in 1 2 3 4 5 6 7 8 9 10
	do
	    dig @127.0.0.1 -p 8053 example soa |
		grep $serial  && break
	    echo zone is not signed yet, sleeping
	    sleep 1
	done
	dig @127.0.0.1 -p 8053 example soa |
	    grep $serial ||
		{
		    echo zone is not signed yet, giving up
		    exit 1
		}
	$CASCADE zone remove example
done
