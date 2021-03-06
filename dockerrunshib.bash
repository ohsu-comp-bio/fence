#!/bin/bash

#
# Update certificate authority index -
# environment may have mounted more authorities
#
update-ca-certificates
#
# Kubernetes may mount jwt-keys as a tar ball
#
if [ -f /fence/jwt-keys.tar ]; then
  (
    cd /fence
    tar xvf jwt-keys.tar
    if [ -d jwt-keys ]; then
      mkdir -p keys
      mv jwt-keys/* keys/
    fi
  )
fi
service shibd start
sed -i "s/ServerName SERVERNAME/ServerName https:\/\/$HOSTNAME/g" /etc/apache2/sites-available/fence.conf
rm -rf /var/run/apache2/apache2.pid
/usr/sbin/apache2ctl -D FOREGROUND
