#!/bin/bash

username=${username:-}
password=${password:-}
credential_err=false

# Check if username is set
if [[ -z $username ]]
then
    echo "ERR: username is empty, please add username in ENV"
    credential_err=true
fi

# Check if password is set
if [[ -z $password ]]
then
    echo "ERR: password is empty, please add password in ENV"
    credential_err=true
fi

# Terminate the entrypoint script when either username or password is empty
if [ "$credential_err" == true ]
then 
    exit 1
fi


#configuring timezone
echo ${timezone} > /etc/timezone
cp /usr/share/zoneinfo/${timezone} /etc/localtime

#execute custom script for 1st time
python /usr/python/redis_surfshark.py

#keep system running after executing script
tail -f /dev/null