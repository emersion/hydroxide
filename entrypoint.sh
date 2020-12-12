#!/bin/sh

#TODO: Learn to use issues XD
#TODO: Consider using arguments
#TODO: Check for empty strings
#TODO: allow for non-2FA? Seems really insecure as the password would linger in the container. Then again there's no session timeouts on the bridge and the token is stored under ~/.config/hydroxide/auth.json

if [ "${TOKEN}" ]
then
  printf "%s\n%s\n" "${PASSWORD}" "${TOKEN}" | ./hydroxide auth $USERNAME
else
  printf "\nNo two factor token provided\n"
  exit 1
fi;

./hydroxide serve
