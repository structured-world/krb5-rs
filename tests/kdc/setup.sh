#!/bin/bash
set -euo pipefail
if [[ "${DEBUG_KDC_SETUP:-0}" == "1" ]]; then
    set -x
fi

export DEBIAN_FRONTEND=noninteractive

# Allow overriding credentials via env vars so secrets don't appear in ps output.
# The default values below are for local testing only and MUST NOT be reused outside tests.
MASTER_KEY="${KDC_MASTER_KEY:-masterkey}"
TESTUSER1_PASSWORD="${KDC_TESTUSER1_PASSWORD:-testpassword}"
TESTUSER2_PASSWORD="${KDC_TESTUSER2_PASSWORD:-password2}"

# Install MIT KDC (krb5.conf must not be bind-mounted during install
# because krb5-config postinst tries to rename it)
apt-get update -qq
apt-get install -y -qq krb5-kdc krb5-admin-server

# Write config files (overwrite the defaults created by package install)
cat > /etc/krb5.conf <<'CONF'
[libdefaults]
    default_realm = TEST.REALM
    dns_lookup_realm = false
    dns_lookup_kdc = false
[realms]
    TEST.REALM = {
        kdc = 127.0.0.1:88
        admin_server = 127.0.0.1:749
    }
CONF

cat > /etc/krb5kdc/kdc.conf <<'CONF'
[kdcdefaults]
    kdc_ports = 88
    kdc_tcp_ports = 88
[realms]
    TEST.REALM = {
        database_name = /var/lib/krb5kdc/principal
        admin_keytab = /var/lib/krb5kdc/kadm5.keytab
        acl_file = /etc/krb5kdc/kadm5.acl
        key_stash_file = /etc/krb5kdc/stash
        max_life = 24h
        max_renewable_life = 7d
        supported_enctypes = aes256-cts-hmac-sha1-96:normal aes128-cts-hmac-sha1-96:normal
        default_principal_flags = +preauth
    }
CONF

# Create KDC database
mkdir -p /var/lib/krb5kdc
# -W reads password from stdin; kdb5_util prompts twice (enter + verify)
printf '%s\n%s\n' "$MASTER_KEY" "$MASTER_KEY" | kdb5_util create -s -r TEST.REALM -W

# Create test principals
printf '%s\n%s\n' "$TESTUSER1_PASSWORD" "$TESTUSER1_PASSWORD" | \
    kadmin.local -q "addprinc testuser@TEST.REALM"
printf '%s\n%s\n' "$TESTUSER2_PASSWORD" "$TESTUSER2_PASSWORD" | \
    kadmin.local -q "addprinc testuser2@TEST.REALM"
kadmin.local -q "addprinc -randkey HTTP/server.test.realm@TEST.REALM"

echo "KDC initialized. Starting..."

# Enable KDC logging
cat >> /etc/krb5.conf << 'LOGGING'

[logging]
    kdc = STDERR
    admin_server = STDERR
    default = STDERR
LOGGING

# Start KDC in foreground
exec krb5kdc -n
