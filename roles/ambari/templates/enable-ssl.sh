#!/usr/bin/env bash
# {# -*- ShellScript -*- #}
# Enable SSL for Hadoop Web UIs
#
#TODO add support for multiple Ranger Admin hosts
#TODO automatically figure out the hostnames for each component
#TODO add ranger yarn plugin ssl
#TODO add ranger hive plugin ssl

set -x

propc=0
rm -f /var/tmp/ambari.properties.1
cp /etc/ambari-server/conf/ambari.properties /var/tmp/ambari.properties.1

NAMENODE_SERVER_ONE="{{ SSL_NN }}"
ALL_NAMENODE_SERVERS="{{ SSL_NNS }}"

RESOURCE_MANAGER_SERVER_ONE="{{ SSL_RM }}"
HISTORY_SERVER="{{ SSL_HS }}"

HBASE_MASTER_SERVER_ONE="{{ SSL_HBM }}"
ALL_HBASE_MASTER_SERVERS="{{ SSL_HBMS }}"
ALL_HBASE_REGION_SERVERS="{{ SSL_HBRS }}"

HIVE_SERVER_ONE="{{ SSL_HV }}"
ALL_HIVE_SERVERS="{{ SSL_HV_ALL }}"

RANGER_ADMIN_SERVER="{{ SSL_RA }}"

OOZIE_SERVER_ONE="{{ SSL_OO }}"
ALL_OOZIE_SERVERS="{{ SSL_OOS }}"

#HUE_SERVER="{{ SSL_HUE }}"
ALL_HUE_SERVERS="{{ SSL_HUE_ALL }}"

HTTPFS_SERVER="{{ SSL_HTTPFS }}"
ALL_HTTPFS_SERVERS="{{ SSL_HTTPFS_ALL }}"

ALL_HADOOP_SERVERS="{{ SSL_ALL }}"
ALL_REAL_SERVERS="$ALL_HADOOP_SERVERS {{ SSL_AS[0] }}"
DOMAIN=$(hostname -d) 
SSL_C="{{ SSL_C }}"
SSL_ST="{{ SSL_ST }}"
SSL_L="{{ SSL_L }}"
SSL_O="{{ SSL_O }}"
SSL_OU="{{ SSL_OU }}"
SSL_EM="{{ SSL_EM }}"

export AMBARI_SERVER="{{ SSL_AS[0] }}"
AMBARI_PASS="{{ AMBARI_PASSWORD }}"
CLUSTER_NAME="{{ CLUSTER_NAME }}"

#
# PREP
#
mkdir -p /tmp/security
chmod -R 755 /tmp/security
cd /tmp/security || exit 1
TRUST_STORE=/etc/pki/java/cacerts
SERIAL="{{ range(1, 2000000000) | random }}"

#remove ssh host key checks
cat <<EOF > ~/.ssh/config
Host *
 PasswordAuthentication no
 StrictHostKeyChecking no
 ConnectTimeout 20
EOF

# generate a random password
randpass1=changeit #$(openssl rand -base64 32)
randpass2=password
echo $randpass1 >/root/.enable-ssl.pw1
echo $randpass2 >/root/.enable-ssl.pw2

#generate an ssh key for passwordless ssh if this is on the sandbox
if echo "$AMBARI_SERVER" | grep -q -i "sandbox.hortonworks.com" ; then
    if [ ! -e ~/.ssh/id_rsa ]; then
        ssh-keygen -f ~/.ssh/id_rsa -N "" -q
    fi
    cat ~/.ssh/id_rsa.pub >> ~/.ssh/authorized_keys
    chmod 600 ~/.ssh/authorized_keys
fi

# Copy over configs.sh from Ambari server to what ever server this is.
# This enables running this script on another host (ansible host, for example).
if [ ! -e "/var/lib/ambari-server/resources/scripts/configs.sh" ]; then
    mkdir -p /var/lib/ambari-server/resources/scripts/
    scp "${AMBARI_SERVER}:/var/lib/ambari-server/resources/scripts/configs.sh" /var/lib/ambari-server/resources/scripts/
fi

################################################################################
########## Certificate generation related
# 0. Rename any .pem file like hst.tst.com.pem or hst.tst.com_private.pem.
function rename_pem() {
    PUB=''
    PRV=''
    for ii in *.pem; do
        if [ "$ii" = '*.pem' ] ; then break ; fi
        if echo "$ii" | grep -q _private.pem ; then
            PRV="$(basename _private.pem).key"
            if [ ! -e "$PRV" ] ; then
                ln -s "$ii" "$PRV"
            fi
        else
            PUB="$(basename .pem).crt"
            if [ ! -e "$PUB" ] ; then
                ln -s "$ii" "$PUB"
            fi
        fi
    done

    if [ "$SINGLECRT" = 'true' ] && [ ! -e "${DOMAIN}.crt" ] && [ -n "$PUB" ]; then
        cp "$PUB" "${DOMAIN}.crt"
    fi
    if [ "$SINGLECRT" = 'true' ] && [ ! -e "${DOMAIN}.key" ] && [ -n "$PRV" ]; then
        cp "$PRV" "${DOMAIN}.key"
    fi
}

# 1. CA SSL certificate
function ca_crt() {
    if [ -e "ca.crt" ] || [ -e "${DOMAIN}.crt" ]; then return ; fi
    openssl genrsa -out ca.key 2048
    openssl req -new -x509 -days 1826 -key ca.key -out ca.crt \
        -subj "/C=${SSL_C}/ST=${SSL_ST}/L=${SSL_L}/O=${SSL_O}/OU=${SSL_OU}/CN=${SSL_O}/emailAddress=${SSL_EM}"
}

# 2. Server SSL certificates
function make_crt() {
    NAME=$1
    if [ $# -gt 1 ] ; then
        SAN="/subjectAltName=${2}"
    else
        SAN=''
    fi
    if [ $# -gt 2 ] ; then
        CN=$3
    else
        CN=$NAME
    fi
    openssl req -new -newkey rsa:2048 -nodes -keyout "${NAME}.key" -out "${NAME}.csr" \
        -subj "/C=${SSL_C}/ST=${SSL_ST}/L=${SSL_L}/O=${SSL_O}/OU=${SSL_OU}/CN=${CN}/emailAddress=${SSL_EM}${SAN}"
    openssl ca -batch -startdate 20160101120000Z -cert ca.crt \
        -keyfile ca.key -out "${NAME}.crt" -infiles "${NAME}.csr"
}

function make_shared_self_crt() {
    if [ ! -e "${DOMAIN}.crt" ]; then
        ii=1
        SAN=''
        for host in ${ALL_REAL_SERVERS}; do
            if [ $ii -gt 1 ] ; then SAN="$SAN," ; fi
            SAN="${SAN}DNS.${ii}=${host}"
            let ii=$ii+1
        done
        make_crt "$DOMAIN" "${SAN}"
    fi

    for host in ${ALL_REAL_SERVERS}; do
        if [ -e "${host}.crt" ] ; then continue; fi
        ln -s "${DOMAIN}.key" "${host}.key"
        ln -s "${DOMAIN}.crt" "${host}.crt"
    done
}

function make_server_crt() {
    for host in ${ALL_REAL_SERVERS}; do
        if [ -e "${host}.crt" ] ; then continue; fi
        make_crt "$host"
    done
}

# 3. Generate an SSL cert for just the domain name of the cluster,
#    which is needed for Oozie
function domain_crt() {
    if [ -e "${DOMAIN}.crt" ]; then return ; fi
    make_cert "$DOMAIN" '' "*.${DOMAIN}"
}

# 4. Copy public ssl certs to all hosts
function copy_crts() {
    for host in ${ALL_REAL_SERVERS}; do
        dfile="/tmp/security/.${host}"
        if [ -e "$dfile" ] ; then continue ; fi
        # shellcheck disable=SC2086
        if [ "$(openssl rsa -noout -modulus -in $host.key)" != "$(openssl x509 -noout -modulus -in $host.crt)" ] ; then
            echo "$host failed verification of private key and public key pair"
        else
            echo "$host verified private key and public key pair"
        fi

        if [ -e "ca.crt" ] ; then
            scp ca.crt "${host}:/tmp/ca.crt"
            ssh "$host" "keytool -import -noprompt -alias myOwnCA -file /tmp/ca.crt -storepass \"$randpass1\" -keystore \"$TRUST_STORE\"; rm -f /tmp/ca.crt" # shellcheck disable=SC2029
        fi

        dhost=0
        for cert in ${ALL_REAL_SERVERS}; do
            scp "$cert.crt" "${host}:/tmp/$cert.crt"
            ssh "$host" "keytool -import -noprompt -alias \"$cert\" -file \"/tmp/${cert}.crt\" -storepass \"$randpass1\" -keystore \"$TRUST_STORE\" ; rm -f \"/tmp/${cert}.crt\"" # shellcheck disable=SC2029
            rval=$?
            if [ $rval -ne 0 ] ; then dhost=$rval ; fi
        done
        if [ $dhost -eq 0 ] ; then touch "$dfile" ; fi
    done
}

########## Certificate format related
function build_p12() {
    inname=$1
    ouname=$2
    pkname=$3
    cafile=''
    if [ -e ca.crt ] ; then cafile='-CAfile ca.crt -chain'; fi
    # shellcheck disable=SC2086
    openssl pkcs12 -export -in "${inname}.crt" -inkey "${inname}.key" \
        -out "${ouname}.p12" -name "$pkname" $cafile -passout "pass:$randpass2"
}

function keytool_import() {
    KEYSTORE=$1
    SRCSTORE=$2
    ALIAS=$3
    rm -f "$KEYSTORE"
    if [ -e ca.crt ] ; then
        keytool -import -noprompt -alias myOwnCA -file ca.crt \
            -storepass "$randpass2" -keypass "$randpass2" -keystore "$KEYSTORE"
    fi
    keytool -importkeystore -noprompt -deststorepass "$randpass2" \
        -destkeypass "$randpass2" -destkeystore "$KEYSTORE" \
        -srckeystore "${SRCSTORE}.p12" -srcstoretype PKCS12 \
        -srcstorepass "$randpass2" -alias "$ALIAS"
    if [ $# -eq 4 ] ; then
        ADMHOST=$4
        keytool -import -noprompt -alias rangeradmintrust -file "${ADMHOST}.crt" \
            -storepass "$randpass2" -keystore "${KEYSTORE}"
    fi
}

function keystore_copy() {
    KEYSTORE=$1
    shift
    DPATH=$1
    shift
    OWNER=$1
    shift
    for host in "$@" ; do
        scp "$KEYSTORE" "${host}:${DPATH}/${KEYSTORE}"
        # shellcheck disable=SC2029
        ssh "$KEYSTORE" "chmod 440 \"${DPATH}/$KEYSTORE\";chown \"$OWNER\" \"${DPATH}/$KEYSTORE\""
    done
}

######## Ambari related
function copyAmbariProp() {
    if [ -s /etc/ambari-server/conf/ambari.properties ] ; then
        cur=$(md5sum /etc/ambari-server/conf/ambari.properties | awk '{ print $1; }')
        if [ -e "/var/tmp/ambari.properties.$propc" ] ; then
            pre=$(md5sum /var/tmp/ambari.properties.$propc | awk '{ print $1; }')
        else
            let propc=$propc-1
            pre=0
        fi
        if [ "$cur" != "$pre" ] ; then
            let propc=$propc+1
            cp -f /etc/ambari-server/conf/ambari.properties /var/tmp/ambari.properties.$propc
            echo "INFO: /etc/ambari-server/conf/ambari.properties changed"
        fi
    else
        echo "ERROR: /etc/ambari-server/conf/ambari.properties is empty"
        cp -f /var/tmp/ambari.properties.$propc /etc/ambari-server/conf/ambari.properties
    fi
}

function ambariConf() {
    if [ -z "$*" ] ; then return ; fi
    /var/lib/ambari-server/resources/scripts/configs.sh -u admin -p "$AMBARI_PASS" \
        -port "{{AMBARI_SERVER_SSL_PORT}}" -s set "$AMBARI_SERVER" "$CLUSTER_NAME" \
        "$@" &> /dev/null || echo "Failed to change $* in Ambari"
    rm -f doSet_version*
}

function ambariGet() {
    if [ -z "$*" ] ; then return ; fi
    /var/lib/ambari-server/resources/scripts/configs.sh -u admin -p "$AMBARI_PASS" \
        -port "{{AMBARI_SERVER_SSL_PORT}}" -s get "$AMBARI_SERVER" "$CLUSTER_NAME" "$@"
    rm -f doSet_version*
}

function make_ssl-exp() {
    cat <<EOF > ambari-ssl-expect.exp
#!/usr/bin/expect
spawn "/usr/sbin/ambari-server" "setup-security" "-j" "{{ AMBARI_JAVA_HOME }}"
expect "Enter choice"
send "1\r"
expect "Do you want to configure HTTPS" { send "y\r" } "Do you want to disable HTTPS" { send "n\r" }
expect "SSL port"
send "\r"
expect "Enter path to Certificate"
send "/tmp/security/{{ SSL_AS[0] }}.crt\r"
expect "Enter path to Private Key"
send "/tmp/security/{{ SSL_AS[0] }}.key\r"
expect "Please enter password for Private Key"
send "\r"
send "\r"
interact
EOF
}
function make_truststore-exp() {
# The Path to TrustStore file must match $TRUST_STORE.
    cat <<EOF > ambari-truststore-expect.exp
#!/usr/bin/expect
spawn "/usr/sbin/ambari-server" "setup-security" "-j" "{{ AMBARI_JAVA_HOME }}"
expect "Enter choice"
send "4\r"
expect "Do you want to configure a truststore"
send "y\r"
expect "TrustStore type"
send "jks\r"
expect "Path to TrustStore file"
send "/etc/pki/java/cacerts\r"
expect "Password for TrustStore"
send "${randpass1}\r"
expect "Re-enter password"
send "${randpass1}\r"
interact
EOF
}
function make_cert-ca-exp() {
    cat <<EOF > ambari-certificate-ca-expect.exp
#!/usr/bin/expect
spawn "/usr/sbin/ambari-server" "setup-security" "-j" "{{ AMBARI_JAVA_HOME }}"
expect "Enter choice"
send "5\r"
expect "Do you want to configure a truststore"
send "y\r"
expect "Do you want to import a certificate"
send "y\r"
expect "Please enter an alias for the certificate"
send "ca\r"
expect "Enter path to certificate"
send "ca.crt\r"
interact
EOF
}
function make_cert-dom-exp() {
    cat <<EOF > ambari-certificate-domain-expect.exp
#!/usr/bin/expect
spawn "/usr/sbin/ambari-server" "setup-security" "-j" "{{ AMBARI_JAVA_HOME }}"
expect "Enter choice"
send "5\r"
expect "Do you want to configure a truststore"
send "y\r"
expect "Do you want to import a certificate"
send "y\r"
expect "Please enter an alias for the certificate"
send "${DOMAIN}\r"
expect "Enter path to certificate"
send "${DOMAIN}.crt\r"
interact
EOF
}
function make_cert-ooz-exp() {
    cat <<EOF > ambari-certificate-oozie-expect.exp
#!/usr/bin/expect
spawn "/usr/sbin/ambari-server" "setup-security" "-j" "{{ AMBARI_JAVA_HOME }}"
expect "Enter choice"
send "5\r"
expect "Do you want to configure a truststore"
send "y\r"
expect "Do you want to import a certificate"
send "y\r"
expect "Please enter an alias for the certificate"
send "${OOZIE_SERVER_ONE}\r"
expect "Enter path to certificate"
send "${OOZIE_SERVER_ONE}.crt\r"
interact
EOF
}

function https_link() {
    # This is needed to fix ansible startup after boot.
    if [ ! -e /var/lib/ambari-server/keys/https.pass.txt ] ; then
        pushd /var/lib/ambari-server/keys
        ln -s pass.txt https.pass.txt
        popd
    fi
    if [ ! -e /var/lib/ambari-server/keys/https.keystore.p12 ] ; then
        pushd /var/lib/ambari-server/keys
        ln -s keystore.p12 https.keystore.p12
        popd
    fi
}

######### HBase related
function make_ssl-server() {
    cat >/tmp/ssl-server.xml <<EOF
<configuration>
    <property>
      <name>ssl.server.keystore.keypassword</name>
      <value>${randpass2}</value>
    </property>
    <property>
      <name>ssl.server.keystore.location</name>
      <value>/etc/hadoop/conf/hadoop-private-keystore.jks</value>
    </property>
    <property>
      <name>ssl.server.keystore.password</name>
      <value>${randpass2}</value>
    </property>
    <property>
      <name>ssl.server.keystore.type</name>
      <value>jks</value>
    </property>
    <property>
      <name>ssl.server.truststore.location</name>
      <value>${TRUST_STORE}</value>
    </property>
    <property>
      <name>ssl.server.truststore.password</name>
      <value>${randpass1}</value>
    </property>
    <property>
      <name>ssl.server.truststore.reload.interval</name>
      <value>10000</value>
    </property>
    <property>
      <name>ssl.server.truststore.type</name>
      <value>jks</value>
    </property>
</configuration>
EOF
}
function make_ssl-client() {
    cat >/tmp/ssl-client.xml <<EOF
<configuration>
    <property>
      <name>ssl.client.keystore.location</name>
      <value>${TRUST_STORE}</value>
    </property>
    <property>
      <name>ssl.client.keystore.password</name>
      <value>${randpass1}</value>
    </property>
    <property>
      <name>ssl.client.keystore.type</name>
      <value>jks</value>
    </property>
    <property>
      <name>ssl.client.truststore.location</name>
      <value>${TRUST_STORE}</value>
    </property>
    <property>
      <name>ssl.client.truststore.password</name>
      <value>${randpass1}</value>
    </property>
    <property>
      <name>ssl.client.truststore.reload.interval</name>
      <value>10000</value>
    </property>
    <property>
      <name>ssl.client.truststore.type</name>
      <value>jks</value>
    </property>
</configuration>
EOF
}
function hbaseSSLfix() {
    # Ambari is broken. It should have deployed these files.
    make_ssl-server
    make_ssl-client
    for ii in ssl-client.xml ssl-server.xml ; do
        # This does not work here, because values have not been set:
        #scp "${NAMENODE_SERVER_ONE}:/etc/hadoop/conf/$ii" /tmp/$ii
        for host in ${ALL_HBASE_MASTER_SERVERS}; do
            scp /tmp/$ii "${host}:/etc/hbase/conf/$ii"
        done
        for host in ${ALL_HBASE_REGION_SERVERS}; do
            scp /tmp/$ii "${host}:/etc/hbase/conf/$ii"
        done
    done
}

######### Hue related
function make_publickeys_pem() {
    if [ "$SINGLECRT" = 'true' ] ; then
        if [ ! -e "${DOMAIN}.pem" ] ; then
            openssl x509 -in "${DOMAIN}.crt" -out "${DOMAIN}.pem"
        fi
        rm -f publickeys.pem
        cp "${DOMAIN}.pem" publickeys.pem
    else
        if [ ! -e "ca.pem" ] && [ -e "ca.crt" ] ; then
            openssl x509 -in 'ca.crt' -out 'ca.pem'
        fi
        for host in ${ALL_HADOOP_SERVERS}; do
            if [ ! -e "${host}.pem" ] ; then
                openssl x509 -in "${host}.crt" -out "${host}.pem"
            fi
        done
        rm -f publickeys.pem
        cat ./*.pem >publickeys.pem
    fi
}

################################################################################
##### externally named functions
#
# create all SSL certificates, and keys
#
function generateSSLCerts() {
    rm -f /etc/pki/CA/index.txt
    touch /etc/pki/CA/index.txt
    echo "$SERIAL" > /etc/pki/CA/serial
    rename_pem
    ca_crt
    if [ "$SINGLECRT" = 'true' ] ; then
        make_shared_self_crt
    else
        make_server_crt
    fi
    domain_crt
    copy_crts
}

#
# Enable Ambari SSL encryption and truststore.
#
function ambariSSLEnable() {
    rpm -q expect || yum install -y expect
    make_ssl-exp
    make_truststore-exp
    make_cert-ca-exp
    make_cert-dom-exp
    make_cert-ooz-exp

    if grep -q 'api.ssl=true' /etc/ambari-server/conf/ambari.properties; then
        echo "SSL is enabled"
    else
        if [ -x /sbin/stop ] ; then /sbin/stop ambari-server ; fi
        service ambari-server stop
        expect ambari-ssl-expect.exp
        expect ambari-truststore-expect.exp
        if grep -q 'api.ssl=true' /etc/ambari-server/conf/ambari.properties; then
            echo "SSL is enabled"
        elif [ -f /root/ambari.properties ] ; then
            echo "SSL configuration failed, deploying file"
            cp /root/ambari.properties /etc/ambari-server/conf
        fi
    fi
    expect ambari-ssl-expect.exp

    if [ -e ca.crt ] ; then
        expect ambari-certificate-ca-expect.exp
    fi
    # Tell ambari about the domain certificate.
    expect ambari-certificate-domain-expect.exp
    # Try to make ambari's oozie check happy about Oozie's certificate.
    expect ambari-certificate-oozie-expect.exp

    https_link

    if [ -x /sbin/start ] ; then
        /sbin/start ambari-server
    else
        service ambari-server start
    fi

    #validate wget -O-  --no-check-certificate "https://${AMBARI_SERVER}:{{AMBARI_SERVER_SSL_PORT}}/#/main/dashboard/metrics"
}

#
# Enable Hadoop UIs SSL encryption. Stop all Hadoop components first
#
function hadoopSSLEnable() {
    for host in ${ALL_HADOOP_SERVERS}; do
        if [ ! -e "${host}.p12" ]; then build_p12 "$host" "$host" "$host"; fi
        keytool_import hadoop-private-keystore.jks "$host" "$host"
        # shellcheck disable=SC2086
        keystore_copy hadoop-private-keystore.jks /etc/hadoop/conf yarn:hadoop "$host"
    done

    ambariConf hdfs-site 'dfs.https.enable' 'true'
    ambariConf hdfs-site 'dfs.http.policy' 'HTTPS_ONLY'
    ambariConf hdfs-site 'dfs.datanode.https.address' '0.0.0.0:50475'
    ambariConf hdfs-site 'dfs.namenode.https-address' '0.0.0.0:50470'

    ambariConf core-site 'hadoop.ssl.require.client.cert' 'false'
    ambariConf core-site 'hadoop.ssl.hostname.verifier' 'DEFAULT'
    ambariConf core-site 'hadoop.ssl.keystores.factory.class' 'org.apache.hadoop.security.ssl.FileBasedKeyStoresFactory'
    ambariConf core-site 'hadoop.ssl.server.conf' 'ssl-server.xml'
    ambariConf core-site 'hadoop.ssl.client.conf' 'ssl-client.xml'

    ambariConf mapred-site 'mapreduce.jobhistory.http.policy' 'HTTPS_ONLY'
    ambariConf mapred-site 'mapreduce.jobhistory.webapp.https.address' "${HISTORY_SERVER}:19443"
    ambariConf mapred-site 'mapreduce.jobhistory.webapp.address' "${HISTORY_SERVER}:19443"

    ambariConf yarn-site 'yarn.http.policy' 'HTTPS_ONLY'
    ambariConf yarn-site 'yarn.log.server.url' "https://${HISTORY_SERVER}:19443/jobhistory/logs"
    ambariConf yarn-site 'yarn.resourcemanager.webapp.https.address' "${RESOURCE_MANAGER_SERVER_ONE}:8090"
    ambariConf yarn-site 'yarn.nodemanager.webapp.https.address' '0.0.0.0:45443'

    ambariConf ssl-server 'ssl.server.keystore.password' "$randpass2"
    ambariConf ssl-server 'ssl.server.keystore.keypassword' "$randpass2"
    ambariConf ssl-server 'ssl.server.keystore.location' '/etc/hadoop/conf/hadoop-private-keystore.jks'
    ambariConf ssl-server 'ssl.server.truststore.location' "$TRUST_STORE"
    ambariConf ssl-server 'ssl.server.truststore.password' "$randpass1"

    ambariConf ssl-client 'ssl.client.keystore.location' "$TRUST_STORE"
    ambariConf ssl-client 'ssl.client.keystore.password' "$randpass1"
    ambariConf ssl-client 'ssl.client.truststore.password' "$randpass1"
    ambariConf ssl-client 'ssl.client.truststore.location' "${TRUST_STORE}"

    # In Ambari, perform Start ALL
}

#
# Enable Hive endpoint SSL encryption.
#
function hiveSSLEnable() {
    for host in ${ALL_HIVE_SERVERS}; do
        if [ ! -e "${host}.p12" ]; then build_p12 "$host" "$host" "$host"; fi
        keytool_import hadoop-private-keystore.jks "$host" "$host"
        # shellcheck disable=SC2086
        keystore_copy hive-private-keystore.jks /etc/hive/conf yarn:hadoop "$host"
    done

    ambariConf 'hive-site' 'hive.server2.use.SSL' 'true'
    ambariConf 'hive-site' 'hive.server2.keystore.path' '/etc/hive/conf/hive-private-keystore.jks'
    ambariConf 'hive-site' 'hive.server2.keystore.password' "$randpass2"
}

#
# Enable HBase UI SSL encryption.  Stop all HBase services first
#
## each host gets its own SSL certificate
## some of the keyimports may fail because the HBase services run on the same hosts as the Hadoop services
function hbaseSSLEnable() {
    #copy ssl private cert to all hbase masters
    for host in ${ALL_HBASE_MASTER_SERVERS}; do
        if [ ! -e "${host}.p12" ]; then build_p12 "$host" "$host" "$host"; fi
        keytool_import hadoop-private-keystore.jks "$host" "$host"
        # shellcheck disable=SC2086
        keystore_copy hadoop-private-keystore.jks /etc/hbase/conf hbase:hadoop "$host"
    done

    hbaseSSLfix

    ambariConf hbase-site 'hbase.ssl.enabled' 'true'
    ambariConf hbase-site 'hbase.rest.ssl.enabled' 'true'
    ambariConf hbase-site 'hbase.rest.ssl.keystore.store' '/usr/hbase/conf/hadoop-private-keystore.jks'
    ambariConf hbase-site 'hbase.rest.ssl.keystore.password' "$randpass2"
    ambariConf hbase-site 'hbase.rest.ssl.keystore.keypassword' "$randpass2"

    # In Ambari, perform Start ALL
    #validate through: openssl s_client -connect ${HBASE_MASTER_SERVER_ONE}:16010 -showcerts  < /dev/null
}

#
# Enable Oozie UI SSL encryption
#
function oozieSSLEnable() {
    build_p12 "$DOMAIN" oozie-server tomcat

    #copy and add private key to oozie servers
    for host in ${ALL_OOZIE_SERVERS}; do
        if [ ! -e "${host}_tomcat.p12" ]; then build_p12 "$host" "${host}_tomcat" tomcat; fi
        keytool_import .keystore "${host}_tomcat" tomcat
        # shellcheck disable=SC2086
        keystore_copy .keystore /var/lib/oozie oozie:oozie "$host"
    done

    #copy the public key to all servers and add to truststore
    for host in ${ALL_REAL_SERVERS}; do
        scp "${DOMAIN}.crt" "${host}:/tmp/${DOMAIN}.crt"
        # shellcheck disable=SC2029
        ssh "$host" "
        keytool -import -noprompt -alias tomcat -file /tmp/${DOMAIN}.crt -storepass \"$randpass1\" -keystore $TRUST_STORE;
        rm -f \"/tmp/${DOMAIN}.crt\";
        "
    done

    #make changes to Ambari to set oozie.base.url and add OOZIE_HTTP(S)_PORT
    ambariConf oozie-site 'oozie.http.port' '11443'
    ambariConf oozie-site 'oozie.base.url' "https://${OOZIE_SERVER_ONE}:11443/oozie"
    ambariGet 'oozie-env' 'oozie-env'
    perl -pe "s|(\"content\".*?) ?\",$|\$1\\\\nexport OOZIE_HTTP_PORT=11000\\\\nexport OOZIE_HTTPS_PORT=11443\\\\nexport CATALINA_OPTS=\\\\\"\\\$CATALINA_OPTS -Doozie.https.port=\\\${OOZIE_HTTPS_PORT} -Doozie.https.keystore.pass=${randpass2}\\\\\"\\\\nexport OOZIE_BASE_URL=https://${OOZIE_SERVER_ONE}:11443/oozie\\\\n\",|" -i oozie-env
    ambariConf 'oozie-env' 'oozie-env'

    ssh "${OOZIE_SERVER_ONE}" /usr/hdp/current/oozie-server/bin/oozie-setup.sh prepare-war -secure
    if [ $? -ne 0 ] ; then
        ssh "${OOZIE_SERVER_ONE}" /usr/hdp/current/oozie-server/oozie-server/bin/oozie-setup.sh prepare-war -secure
    fi

    rm -f oozie-env
    # Now restart Oozie
    #validate using
    # openssl s_client -connect ${OOZIE_SERVER_ONE}:11443 -showcerts  < /dev/null
    # and
    # oozie jobs -oozie  https://${OOZIE_SERVER_ONE}:11443/oozie
    #
}

#
# Enable Ranger Admin UI SSL encryption.  Keep Ranger Admin and Ranger user-sync on the same hostname
#
function rangerAdminSSLEnable() {
    build_p12 "$RANGER_ADMIN_SERVER" ranger-admin rangeradmintrust
    RANGER_PRIVATE_KEYSTORE=ranger-admin-keystore.jks
    keytool_import "$RANGER_PRIVATE_KEYSTORE" ranger-admin rangeradmintrust
    # shellcheck disable=SC2086
    keystore_copy "$RANGER_PRIVATE_KEYSTORE" /etc/ranger/admin/conf \
        ranger:ranger $RANGER_ADMIN_SERVER

    ambariConf 'ranger-admin-site' 'ranger.https.attrib.keystore.file' "/etc/ranger/admin/conf/${RANGER_PRIVATE_KEYSTORE}"
    ambariConf 'ranger-admin-site' 'ranger.service.https.attrib.keystore.file' "/etc/ranger/admin/conf/${RANGER_PRIVATE_KEYSTORE}"
    ambariConf 'ranger-admin-site' 'ranger.service.https.attrib.client.auth' 'false'
    ambariConf 'ranger-admin-site' 'ranger.service.https.attrib.keystore.pass' "$randpass1"
    ambariConf 'ranger-admin-site' 'ranger.service.https.attrib.keystore.keyalias' 'rangeradmintrust'

    ambariConf 'ranger-admin-site' 'ranger.service.http.enabled' 'false'
    ambariConf 'ranger-admin-site' 'ranger.service.https.attrib.clientAuth' 'want'
    ambariConf 'ranger-admin-site' 'ranger.service.https.attrib.keystore.pass' "$randpass2"
    ambariConf 'ranger-admin-site' 'ranger.service.https.attrib.ssl.enabled' 'true'

    ambariConf 'ranger-ugsync-site' 'ranger.usersync.truststore.file' "${TRUST_STORE}"
    ambariConf 'ranger-ugsync-site' 'ranger.usersync.truststore.password' "$randpass1"

    ambariConf 'admin-properties' 'policymgr_external_url' "https://${RANGER_ADMIN_SERVER}:6182"

    #restart Ranger via Ambari
}
#
# Ranger HDFS Plugin
#
# even though there are two NameNodes, the same SSL certificate must be used
function rangerHDFSSSLEnable() {
    build_p12 "$NAMENODE_SERVER_ONE" rangerHdfsAgent rangerHdfsAgent "$RANGER_ADMIN_SERVER"
    RANGER_HDFS_PRIVATE_KEYSTORE=ranger-hdfs-plugin-keystore.jks
    keytool_import "$RANGER_HDFS_PRIVATE_KEYSTORE" rangerHdfsAgent rangerHdfsAgent
    # shellcheck disable=SC2086
    keystore_copy "$RANGER_HDFS_PRIVATE_KEYSTORE" /etc/hadoop/conf \
        hdfs:hadoop $ALL_NAMENODE_SERVERS

    ambariConf 'ranger-hdfs-policymgr-ssl' 'xasecure.policymgr.clientssl.keystore' "/etc/hadoop/conf/${RANGER_HDFS_PRIVATE_KEYSTORE}"
    ambariConf 'ranger-hdfs-policymgr-ssl' 'xasecure.policymgr.clientssl.keystore.password' "$randpass2"
    ambariConf 'ranger-hdfs-policymgr-ssl' 'xasecure.policymgr.clientssl.truststore' "${TRUST_STORE}"
    ambariConf 'ranger-hdfs-policymgr-ssl' 'xasecure.policymgr.clientssl.truststore.password' "$randpass1"

    #add to Ranger Admin UI
    #restart HDFS
    #[root@node1 security]# cat node1.vzlatkin.com.key node1.vzlatkin.com.crt  >> node1.vzlatkin.com.pem
    # [root@node1 security]# curl --cacert /tmp/security/ca.crt --cert /tmp/security/node1.vzlatkin.com.pem "https://node1.vzlatkin.com:6182/service/plugins/policies/download/cluster1_hadoop?lastKnownVersion=3&pluginId=hdfs@node1.vzlatkin.com-cluster1_hadoop"
    # look for "util.PolicyRefresher" in logs
}
#
# Ranger Hive Plugin
#
function rangerHiveSSLEnable() {
    build_p12 "$HIVE_SERVER_ONE" rangerHiveAgent rangerHiveAgent
    RANGER_HIVE_PRIVATE_KEYSTORE=ranger-plugin-keystore.jks
    keytool_import "$RANGER_HIVE_PRIVATE_KEYSTORE" rangerHiveAgent rangerHiveAgent "$RANGER_ADMIN_SERVER"
    # shellcheck disable=SC2086
    keystore_copy "$RANGER_HIVE_PRIVATE_KEYSTORE" hive hive:hadoop $HIVE_SERVER_ONE

    ambariConf 'ranger-hive-policymgr-ssl' 'xasecure.policymgr.clientssl.keystore' "/etc/hive/conf/${RANGER_HIVE_PRIVATE_KEYSTORE}"
    ambariConf 'ranger-hive-policymgr-ssl' 'xasecure.policymgr.clientssl.keystore.password' "$randpass2"
    ambariConf 'ranger-hive-policymgr-ssl' 'xasecure.policymgr.clientssl.truststore' "${TRUST_STORE}"
    ambariConf 'ranger-hive-policymgr-ssl' 'xasecure.policymgr.clientssl.truststore.password' "$randpass1"

    ambariConf 'hive-site' 'hive.security.authenticator.manager' 'org.apache.hadoop.hive.ql.security.SessionStateUserAuthenticator'
}
#
# Ranger HBase Plugin
#
function rangerHBaseSSLEnable() {
    build_p12 "$HBASE_MASTER_SERVER_ONE" rangerHbaseAgent rangerHbaseAgent
    RANGER_HBASE_PRIVATE_KEYSTORE=ranger-hbase-plugin-keystore.jks
    keytool_import "$RANGER_HBASE_PRIVATE_KEYSTORE" rangerHbaseAgent rangerHbaseAgent "$RANGER_ADMIN_SERVER"
    # shellcheck disable=SC2086
    keystore_copy "$RANGER_HBASE_PRIVATE_KEYSTORE" /etc/hadoop/conf \
        hbase:hadoop $ALL_HBASE_MASTER_SERVERS $ALL_HBASE_REGION_SERVERS

    ambariConf 'ranger-hbase-policymgr-ssl' 'xasecure.policymgr.clientssl.keystore' "/etc/hadoop/conf/${RANGER_HBASE_PRIVATE_KEYSTORE}"
    ambariConf 'ranger-hbase-policymgr-ssl' 'xasecure.policymgr.clientssl.keystore.password' "$randpass2"
    ambariConf 'ranger-hbase-policymgr-ssl' 'xasecure.policymgr.clientssl.truststore' "${TRUST_STORE}"
    ambariConf 'ranger-hbase-policymgr-ssl' 'xasecure.policymgr.clientssl.truststore.password' "$randpass1"

    #add CN via Ranger Admin UI
    #restart HBase via Ambari
    #validate via
    # [root@node1 security]#  cat node2.vzlatkin.com.key node2.vzlatkin.com.crt  >> node2.vzlatkin.com.pem
    #[root@node1 security]# curl --cacert /tmp/security/ca.crt --cert /tmp/security/node2.vzlatkin.com.pem "https://node1.vzlatkin.com:6182/service/plugins/policies/download/cluster1_hbase?lastKnownVersion=3&pluginId=hbase@node2.vzlatkin.com-cluster1_hbase"
}

#
# Hue UI
#
function hueSSLEnable() {
    make_publickeys_pem
    for host in ${ALL_HUE_SERVERS}; do
        if [ -e 'ca.pem' ] ; then
            scp ca.pem "${host}:/tmp/ca.pem"
        fi
        scp publickeys.pem "${host}:/etc/hue/conf/cacerts.pem"
        scp "${host}.crt" "${host}:/etc/hue/conf/${host}.crt"
        scp "${host}.key" "${host}:/etc/hue/conf/${host}.key"
        hack='/usr/lib/hue/build/env/lib/python2.6/site-packages/requests-2.2.1-py2.6.egg/requests/sessions.py'
        # shellcheck disable=SC2029
        ssh "${host}" "
            if [ -e '/tmp/ca.pem' ] ; then openssl x509 -in /tmp/ca.pem -text >>/etc/ssl/certs/ca-bundle.crt ; fi
            chown hue:hadoop /etc/hue/conf/${host}.*
            chmod 440 /etc/hue/conf/${host}.*
            chmod -x /etc/hue/conf/*
            sed -r -e '/# Look for configuration./ { n ; s/^(  *)/\\1#/ }' \
                   -e 's/    verify = (os.environ.get..REQUESTS_CA_BUNDLE..)/verify = \"\\/etc\\/hue\\/conf\\/cacerts.pem\" #\1/' -i $hack
            "
            #sed -e '/^DAEMON/ s/=\\\$BIN\\/supervisor/=\"REQUESTS_CA_BUNDLE=\\/etc\\/hue\\/conf\\/cacerts.pem \\\$BIN\\/supervisor\"/' -i /etc/init.d/hue
    done
    hueEnable
}

function hueEnable() {
    # By itself, enabling use of existing function to update Ambari for non-SSL deployment.
    # TODO: replace "hue" with the usename the server runs as
    # shellcheck disable=SC2086
    ambariConf 'core-site' 'hadoop.proxyuser.hue.hosts' "$(echo $ALL_HUE_SERVERS | tr ' ' ',')"
    ambariConf 'core-site' 'hadoop.proxyuser.hue.groups' '*'
    ambariConf 'core-site' 'hadoop.proxyuser.hue.users' '*'
}

#
# Hadoop HTTPFS
#
function httpfsSSLEnable() {
    # shellcheck disable=SC2086
    build_p12 ${HTTPFS_SERVER} httpfsServer httpfsServer
    HTTPFS_PRIVATE_KEYSTORE=httpfs-keystore.jks
    keytool -genkey -alias tomcat -keyalg RSA
    keytool_import "$HTTPFS_PRIVATE_KEYSTORE" httpfsServer httpfsServer "$HTTPFS_SERVER"
    # shellcheck disable=SC2086
    keystore_copy "$HTTPFS_PRIVATE_KEYSTORE" /etc/hadoop-httpfs/conf \
        hdfs:hadoop $ALL_HTTPFS_SERVERS
    httpfsEnable
}

function httpfsEnable() {
    # By itself, enabling use of existing function to update Ambari for non-SSL deployment.
    # TODO: replace "httpfs" with the usename the server runs as
    # shellcheck disable=SC2086
    ambariConf 'core-site' 'hadoop.proxyuser.httpfs.hosts' "$(echo $ALL_HTTPFS_SERVERS | tr ' ' ',')"
    ambariConf 'core-site' 'hadoop.proxyuser.httpfs.groups' '*'
    ambariConf 'core-site' 'hadoop.proxyuser.httpfs.users' '*'
}

function setperms() {
    # Any must be set permission go here.
    for host in ${ALL_REAL_SERVERS}; do
        # shellcheck disable=SC2029
        ssh "$host" "
            chmod 644 \"$TRUST_STORE\"
        "
    done
}

################################################################################
function usage() {
    echo "Usage: $0 [--singleCRT] [--all|--hbaseSSL|--oozieSSL|--hadoopSSL|--rangerSSL|--ambariSSL|--hueSSL|--hue|--httpfsSSL|--httfs]"
    exit 1
}

if [ "$#" -lt 1 ]; then
    usage
fi

SINGLECRT='false'
while [ "$#" -ge 1 ]; do
    key="$1"

    case $key in
        --singleCRT)
            SINGLECRT='true'
        ;;
        --all)
            generateSSLCerts
            ambariSSLEnable
            oozieSSLEnable
            hadoopSSLEnable
            hbaseSSLEnable
            rangerAdminSSLEnable
            rangerHDFSSSLEnable
            rangerHBaseSSLEnable
            hueSSLEnable
            httpfsSSLEnable
        ;;
        --ambariSSL)
            generateSSLCerts
            ambariSSLEnable
        ;;
        --hadoopSSL)
            generateSSLCerts
            hadoopSSLEnable
        ;;
        --hiveSSL)
            generateSSLCerts
            hiveSSLEnable
        ;;
        --hbaseSSL)
            generateSSLCerts
            hbaseSSLEnable
        ;;
        --oozieSSL)
            generateSSLCerts
            oozieSSLEnable
        ;;
        --rangerSSL)
            generateSSLCerts
            rangerAdminSSLEnable
            rangerHDFSSSLEnable
            rangerHBaseSSLEnable
            rangerHiveSSLEnable
        ;;
        --hueSSL)
            generateSSLCerts
            hueSSLEnable
        ;;
        --hue)
            hueEnable
        ;;
        --httpfsSSL)
            generateSSLCerts
            httpfsSSLEnable
        ;;
        --httpfs)
            httpfsEnable
        ;;
        *)
            usage
        ;;
    esac
    shift
done

setperms
