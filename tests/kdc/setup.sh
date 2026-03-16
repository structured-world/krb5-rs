#!/bin/bash
set -e

export DEBIAN_FRONTEND=noninteractive

# Install MIT KDC
apt-get update -qq
apt-get install -y -qq krb5-kdc krb5-admin-server netcat-openbsd >/dev/null 2>&1

# Create KDC database with master password "masterkey"
mkdir -p /var/lib/krb5kdc /etc/krb5kdc
kdb5_util create -s -P masterkey -r TEST.REALM

# Create test principals
# testuser with password "testpassword"
kadmin.local -q "addprinc -pw testpassword testuser@TEST.REALM"
# testuser2 with password "password2" (for multi-user tests)
kadmin.local -q "addprinc -pw password2 testuser2@TEST.REALM"
# Service principal
kadmin.local -q "addprinc -randkey HTTP/server.test.realm@TEST.REALM"

echo "KDC initialized. Starting..."

# Start KDC in foreground
krb5kdc -n
