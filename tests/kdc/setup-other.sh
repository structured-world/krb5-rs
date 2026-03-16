#!/bin/bash
set -euo pipefail
if [[ "${DEBUG_KDC_SETUP:-0}" == "1" ]]; then
    set -x
fi

export DEBIAN_FRONTEND=noninteractive

# Second realm KDC for cross-realm referral testing.
# Creates OTHER.REALM with trust to TEST.REALM.

MASTER_KEY="${KDC_MASTER_KEY:-masterkey2}"
TRUST_PASSWORD="${KDC_TRUST_PASSWORD:-crosstrust}"

apt-get update -qq
apt-get install -y -qq krb5-kdc krb5-admin-server

# Write config — knows about both realms
cat > /etc/krb5.conf <<'CONF'
[libdefaults]
    default_realm = OTHER.REALM
    dns_lookup_realm = false
    dns_lookup_kdc = false
[realms]
    OTHER.REALM = {
        kdc = 127.0.0.1:88
        admin_server = 127.0.0.1:749
    }
    TEST.REALM = {
        kdc = kdc:88
    }
[domain_realm]
    .test.realm = TEST.REALM
    test.realm = TEST.REALM
CONF

cat > /etc/krb5kdc/kdc.conf <<'CONF'
[kdcdefaults]
    kdc_ports = 88
    kdc_tcp_ports = 88
[realms]
    OTHER.REALM = {
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
printf '%s\n%s\n' "$MASTER_KEY" "$MASTER_KEY" | kdb5_util create -s -r OTHER.REALM -W

# Create service principal in OTHER.REALM
kadmin.local -q "addprinc -randkey HTTP/service.other.realm@OTHER.REALM"

# Create cross-realm trust principals (bidirectional).
# Both KDCs must have matching krbtgt principals with the same key.
printf '%s\n%s\n' "$TRUST_PASSWORD" "$TRUST_PASSWORD" | \
    kadmin.local -q "addprinc krbtgt/OTHER.REALM@TEST.REALM"
kadmin.local -q "modprinc -requires_preauth krbtgt/OTHER.REALM@TEST.REALM"
printf '%s\n%s\n' "$TRUST_PASSWORD" "$TRUST_PASSWORD" | \
    kadmin.local -q "addprinc krbtgt/TEST.REALM@OTHER.REALM"
kadmin.local -q "modprinc -requires_preauth krbtgt/TEST.REALM@OTHER.REALM"

echo "OTHER.REALM KDC initialized. Starting..."

cat >> /etc/krb5.conf << 'LOGGING'

[logging]
    kdc = STDERR
    admin_server = STDERR
    default = STDERR
LOGGING

exec krb5kdc -n
