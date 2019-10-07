#!/usr/bin/env bash

# get filename from the first appended script variable
FILE=$1

# check file extension for decryption, else create file for encryption
if [ "${FILE: -4}" == ".enc" ]
then
 openssl enc -aes-256-cbc -pbkdf2 -d -a -in "$FILE" -out tmpfile.txt || exit 1
 vim tmpfile.txt
 openssl enc -aes-256-cbc -pbkdf2 -a -in tmpfile.txt -out "$FILE" || exit 1
 rm -Rf tmpfile.txt
else
 vim "$FILE"
 openssl enc -aes-256-cbc -pbkdf2 -a -in "$FILE" -out "$FILE".enc || exit 1
 rm -Rf "$FILE"
fi
