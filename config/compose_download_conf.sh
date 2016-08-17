#!/bin/sh
export CONFSTORAGE=http://${1}/config/services/

export CONFSTORAGE_OBJDUMP=${CONFSTORAGE}/objdump/
export CONFSTORAGE_PEID=${CONFSTORAGE}/peid/
export CONFSTORAGE_PEINFO=${CONFSTORAGE}/peinfo/
export CONFSTORAGE_VIRUSTOTAL=${CONFSTORAGE}/virustotal/
export CONFSTORAGE_YARA=${CONFSTORAGE}/yara/
export CONFSTORAGE_ZIPMETA=${CONFSTORAGE}/zipmeta/
docker-compose -f ./docker-compose.yml.example up -d --build