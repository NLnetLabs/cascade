#!/bin/sh
export LC_ALL=C

for t in 1 2
do
	ldns-read-zone zones/test$t.zone |
		sed 's/ *;.*//' |
		sort > reference-output/test$t.sorted
done
