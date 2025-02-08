#!/bin/bash
if [ -z "${name}" ]; then
	echo "Error: Inform the 'name' variable when running the command"
	exit 1
fi

MIGRATIONS_DIR="./migrations"
TIMESTAMP=$(date +"%Y%m%d%H%M%S")

echo "-- Migration file created on ${TIMESTAMP}" >"${MIGRATIONS_DIR}/V${TIMESTAMP}__${name}.sql"
echo "INFO: ${MIGRATIONS_DIR}/V${TIMESTAMP}__${name}.sql created"
