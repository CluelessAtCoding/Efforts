#!/bin/bash
# By Cluelessatcoding

# Change the version numbers as required
USER="haproxy"
OPENSSLVERSION="3.0.15"
HAPROXYVERSION="2.8.12"


#Changing things below here may break things
SUDO="sudo"
IFS="."
read -a HAPArray <<< "$HAPROXYVERSION"

# Derive Major Version
HAPROXYMAJORVERSION="${HAPArray[0]}.${HAPArray[1]}"

IFS=" "

# Pretty icons
log_icon="\e[31m✓\e[0m"
log_icon_ok="\e[32m✓\e[0m"
log_icon_nok="\e[31m✗\e[0m"

LOG=$(mktemp)
#LOG=/dev/stdout

print_copy(){
cat <<EO
┌─────────────────────────────────────────────────────────┐
│                                                         │
│           HAProxy with Modsecurity utilising            │
│                      OpenSSL 3.x.x                      │
│                                                         │
│               Cluelessatcoding 2022-2024                │
│                                                         │
│                                                         │
│                                                         │
└─────────────────────────────────────────────────────────┘
EO
}

check_viability(){
    if [ "$EUID" -ne 0 ]
        then echo "Please invoke script with sudo or run as root."
        exit
    fi

}

check_os_family(){
    osidlike=$(grep '^ID_LIKE' /etc/os-release)
    IFS="="
    read -a osidsplit <<< "$osidlike"
    osid=${osidsplit[1]}
    if [[ $osid =~ "rhel" ]]; then
        ScriptOSFamily="CentOS"
    elif [[ $osid =~ "fedora" ]]; then
        ScriptOSFamily="CentOS"
    elif [[ $osid =~ "centos" ]]; then
        ScriptOSFamily="CentOS"
    elif [[ $osid =~ "debian" ]]; then
        ScriptOSFamily="Debian"
    fi
    echo "OS Family is $ScriptOSFamily" 
    IFS=" "
}

run_and_log(){
    $1 &> ${LOG} && {
        _log_icon=$log_icon_ok
    } || {
        _log_icon=$log_icon_nok
        exit_=1
    }
    echo -e "${_log_icon} ${2}"
    [[ $exit_ ]] && { echo -e "\t -> ${_log_icon} $3";  exit; }
}

install_pre-reqs(){
#Install Pre-Requisites
echo "-------------------------------------"
echo "Ensuring Pre-Requisites are installed"
echo "-------------------------------------"
echo ""
if [[ $ScriptOSFamily == "CentOS" ]]; then
    dnf -y install epel-release
    dnf config-manager --set-enabled powertools
    dnf -y update
    dnf -y groupinstall "Development Tools"
    dnf -y install openssl-devel perl pcre-devel zlib-devel systemd-devel wget net-tools libxml2 libxml2-devel expat-devel httpd-devel curl-devel yajl-devel libevent libevent-devel readline-devel ssdeep ssdeep-devel lua lua-devel
elif [[ $ScriptOSFamily == "Debian" ]]; then
    apt -y update
    apt -y upgrade
    apt -y install build-essential
    apt -y install libtool autoconf git lua5.3 liblua5.3-dev libpcre3 libpcre3-dev zlib1g zlib1g-dev libsystemd-dev libxml2 libxml2-dev libexpat1-dev libreadline-dev ssdeep libfuzzy-dev libyajl-dev apache2-dev libevent-dev libcurl4-openssl-dev unzip net-tools
fi
}

create_user(){
#Create the user account if it does not already exist
echo "-------------------------------"
echo "Creating User Account - ${USER}"
echo "-------------------------------"
echo ""
if id "${USER}" &>/dev/null; then
        echo "user ${USER} already exist"
    else
        echo "Creating User ${USER}"
		echo ""
        groupadd ${USER}
        useradd --system -g ${USER} -d /home/${USER}/ -m ${USER} -s /usr/sbin/nologin
    fi
}

create_patchfile(){
#Create the modsecurity patch file
if [[ $ScriptOSFamily == "CentOS" ]]; then
echo "-------------------"
echo "Creating Patch File"
echo "-------------------"
echo ""
cat > /tmp/spoa-modsecurity_Makefile.patch << 'EOL'
--- /usr/src/haproxy-2.4.16/spoa-modsecurity/Makefile   2022-05-11 09:26:29.515365331 +0000
+++ /usr/src/haproxy-2.4.15/spoa-modsecurity/Makefile   2022-04-05 16:09:59.806381854 +0000
@@ -6,19 +6,19 @@
 LD = $(CC)
 
 ifeq ($(MODSEC_INC),)
-MODSEC_INC := modsecurity-2.9.1/INSTALL/include
+MODSEC_INC := ModSecurity/INSTALL/include
 endif
 
 ifeq ($(MODSEC_LIB),)
-MODSEC_LIB := modsecurity-2.9.1/INSTALL/lib
+MODSEC_LIB := ModSecurity/INSTALL/lib
 endif
 
 ifeq ($(APACHE2_INC),)
-APACHE2_INC := /usr/include/apache2
+APACHE2_INC := /usr/include/httpd
 endif
 
 ifeq ($(APR_INC),)
-APR_INC := /usr/include/apr-1.0
+APR_INC := /usr/include/apr-1
 endif
 
 ifeq ($(LIBXML_INC),)
@@ -35,7 +35,7 @@
 
 CFLAGS  += -g -Wall -pthread
 INCS += -Iinclude -I$(MODSEC_INC) -I$(APACHE2_INC) -I$(APR_INC) -I$(LIBXML_INC) -I$(EVENT_INC)
-LIBS += -lpthread  $(EVENT_LIB) -levent_pthreads -lcurl -lapr-1 -laprutil-1 -lxml2 -lpcre -lyajl
+LIBS += -lpthread  $(EVENT_LIB) -levent_pthreads -lcurl -lapr-1 -laprutil-1 -lxml2 -lpcre -lyajl -llua-5.3 -lfuzzy
 
 OBJS = spoa.o modsec_wrapper.o
EOL

elif [[ $ScriptOSFamily == "Debian" ]]; then
cat > /tmp/spoa-modsecurity_Makefile.patch << 'EOL'
--- /usr/src/haproxy-2.4.16/spoa-modsecurity/Makefile   2022-05-11 09:26:29.515365331 +0000
+++ /usr/src/haproxy-2.4.15/spoa-modsecurity/Makefile   2022-04-05 16:09:59.806381854 +0000
@@ -6,11 +6,11 @@
 LD = $(CC)

 ifeq ($(MODSEC_INC),)
-MODSEC_INC := modsecurity-2.9.1/INSTALL/include
+MODSEC_INC := ModSecurity/INSTALL/include
 endif

 ifeq ($(MODSEC_LIB),)
-MODSEC_LIB := modsecurity-2.9.1/INSTALL/lib
+MODSEC_LIB := ModSecurity/INSTALL/lib
 endif

 ifeq ($(APACHE2_INC),)
@@ -35,7 +35,7 @@

 CFLAGS  += -g -Wall -pthread
 INCS += -Iinclude -I$(MODSEC_INC) -I$(APACHE2_INC) -I$(APR_INC) -I$(LIBXML_INC) -I$(EVENT_INC)
-LIBS += -lpthread  $(EVENT_LIB) -levent_pthreads -lcurl -lapr-1 -laprutil-1 -lxml2 -lpcre -lyajl
+LIBS += -lpthread  $(EVENT_LIB) -levent_pthreads -lcurl -lapr-1 -laprutil-1 -lxml2 -lpcre -lyajl -llua5.3 -lfuzzy

 OBJS = spoa.o modsec_wrapper.o
EOL
fi
}

update_root_certificates(){
    curl https://cacerts.digicert.com/DigiCertTLSHybridECCSHA3842020CA1-1.crt -o  /usr/local/share/ca-certificates/DigiCertTLSHybridECCSHA3842020CA1-1.crt
    update-ca-certificates
}

download_openssl(){
# Download OpenSSL
echo "--------------------------"
echo "Downloading OpenSSL ${OPENSSLVERSION}"
echo "--------------------------"
echo ""
curl https://www.openssl.org/source/openssl-${OPENSSLVERSION}.tar.gz -o /usr/src/openssl-${OPENSSLVERSION}.tar.gz
}

extract_openssl(){
# Extract OpenSSL
echo "-------------------------"
echo "Extracting OpenSSL ${OPENSSLVERSION}"
echo "-------------------------"
echo ""
mkdir -p /usr/src/openssl-${OPENSSLVERSION}
tar zxf /usr/src/openssl-${OPENSSLVERSION}.tar.gz -C /usr/src/openssl-${OPENSSLVERSION}
}

download_haproxy(){
# Download HAProxy
echo "--------------------------"
echo "Downloading HAProxy $HAPROXYVERSION"
echo "--------------------------"
echo ""
curl https://www.haproxy.org/download/${HAPROXYMAJORVERSION}/src/haproxy-${HAPROXYVERSION}.tar.gz -o /usr/src/haproxy-${HAPROXYVERSION}.tar.gz
}

extract_haproxy(){
# Extract HAProxy
echo "-------------------------"
echo "Extracting HAProxy $HAPROXYVERSION"
echo "-------------------------"
echo ""
mkdir -p /usr/src/haproxy-$HAPROXYVERSION
tar zxf /usr/src/haproxy-${HAPROXYVERSION}.tar.gz -C /usr/src/haproxy-${HAPROXYVERSION}
}

install_openssl(){
echo "-------------------------------------"
echo "Configuring and Installing OpenSSL ${OPENSSLVERSION}"
echo "-------------------------------------"
echo ""
cd /usr/src/openssl-${OPENSSLVERSION}/openssl-${OPENSSLVERSION}
./config --prefix=/opt/openssl-${OPENSSLVERSION} shared
make
make install
cd ..
}

update_library_links(){
echo "----------------------"
echo "Updating Library Links"
echo "----------------------"
echo ""
cat > /etc/ld.so.conf.d/openssl-${OPENSSLVERSION}.conf  << EOL
/opt/openssl-${OPENSSLVERSION}/lib64
EOL

ldconfig -v
}

clone_spoa_modsecurity(){
echo "------------------------"
echo "Cloning spoa-modsecurity"
echo "------------------------"
echo ""
cd /usr/src/haproxy-${HAPROXYVERSION}/haproxy-${HAPROXYVERSION}
git clone https://github.com/haproxy/spoa-modsecurity.git
}

patch_spoa-modsecurity_makefile(){
echo "----------------------------------"
echo "Patching spoa-modsecurity Makefile"
echo "----------------------------------"
echo ""
cd /usr/src/haproxy-${HAPROXYVERSION}/haproxy-${HAPROXYVERSION}/spoa-modsecurity
patch Makefile < /tmp/spoa-modsecurity_Makefile.patch
}

clone_modsecurity(){
echo "-------------------"
echo "Cloning Modsecurity"
echo "-------------------"
echo ""
cd /usr/src/haproxy-${HAPROXYVERSION}/haproxy-${HAPROXYVERSION}/spoa-modsecurity
git clone --branch v2/master https://github.com/SpiderLabs/ModSecurity.git
}

install_modsecurity(){
echo "------------------------------------"
echo "Configuring and Building Modsecurity"
echo "------------------------------------"
echo ""
cd /usr/src/haproxy-${HAPROXYVERSION}/haproxy-${HAPROXYVERSION}/spoa-modsecurity/ModSecurity
./autogen.sh
./configure --prefix=$PWD/INSTALL --disable-apache2-module --enable-standalone-module --enable-pcre-study --enable-pcre-jit --enable-lua-cache
make
make -C standalone install
mkdir -p $PWD/INSTALL/include
cp standalone/*.h $PWD/INSTALL/include
cp apache2/*.h $PWD/INSTALL/include
}

install_spoa-modsecurity(){
echo "-----------------------------------------"
echo "Compiling and Installing spoa-modsecurity"
echo "-----------------------------------------"
echo ""
cd /usr/src/haproxy-${HAPROXYVERSION}/haproxy-${HAPROXYVERSION}/spoa-modsecurity
make
make install
}

install_haproxy(){
cd /usr/src/haproxy-${HAPROXYVERSION}/haproxy-${HAPROXYVERSION}
echo "----------------------------------"
echo "Configuring and Installing HAProxy"
echo "----------------------------------"
echo ""
mkdir -p /etc/haproxy/cert
mkdir -p /var/log/haproxy
chmod -R 775 /var/log/haproxy
chgrp -R syslog /var/log/haproxy
make TARGET=linux-glibc USE_PCRE=1 USE_OPENSSL=1 SSL_LIB=/opt/openssl-${OPENSSLVERSION}/lib64 SSL_INC=/opt/openssl-${OPENSSLVERSION}/include USE_ZLIB=1 USE_SYSTEMD=1
make install
}

clone_owasp_rules(){
echo "-------------------"
echo "Cloning OWASP Rules"
echo "-------------------"
echo ""
cd /opt/
wget --ca-directory=/etc/ssl/certs https://github.com/SpiderLabs/owasp-modsecurity-crs/zipball/v3.0/master
unzip master
mv SpiderLabs-owasp-modsecurity-crs-a216353 owasp-modsecurity-crs
}

configure_modsecurity(){
echo "---------------------------------"
echo "Performing various Configurations"
echo "---------------------------------"
echo ""
cd owasp-modsecurity-crs
cp crs-setup.conf.example crs-setup.conf

cd rules

mv REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf.example REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf
mv RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf.example RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf

mkdir /opt/modsecurity

cp /usr/src/haproxy-${HAPROXYVERSION}/haproxy-${HAPROXYVERSION}/spoa-modsecurity/ModSecurity/unicode.mapping /opt/modsecurity/unicode.mapping
cp /usr/src/haproxy-${HAPROXYVERSION}/haproxy-${HAPROXYVERSION}/spoa-modsecurity/ModSecurity/modsecurity.conf-recommended /opt/modsecurity/modsecurity.conf

#Update modsecurity.conf
cat >> /opt/modsecurity/modsecurity.conf << 'EOL'

include /opt/owasp-modsecurity-crs/crs-setup.conf
include /opt/owasp-modsecurity-crs/rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf
include /opt/owasp-modsecurity-crs/rules/REQUEST-901-INITIALIZATION.conf
include /opt/owasp-modsecurity-crs/rules/REQUEST-905-COMMON-EXCEPTIONS.conf
include /opt/owasp-modsecurity-crs/rules/REQUEST-910-IP-REPUTATION.conf
include /opt/owasp-modsecurity-crs/rules/REQUEST-911-METHOD-ENFORCEMENT.conf
include /opt/owasp-modsecurity-crs/rules/REQUEST-912-DOS-PROTECTION.conf
include /opt/owasp-modsecurity-crs/rules/REQUEST-913-SCANNER-DETECTION.conf
include /opt/owasp-modsecurity-crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf
include /opt/owasp-modsecurity-crs/rules/REQUEST-921-PROTOCOL-ATTACK.conf
include /opt/owasp-modsecurity-crs/rules/REQUEST-930-APPLICATION-ATTACK-LFI.conf
include /opt/owasp-modsecurity-crs/rules/REQUEST-931-APPLICATION-ATTACK-RFI.conf
include /opt/owasp-modsecurity-crs/rules/REQUEST-932-APPLICATION-ATTACK-RCE.conf
include /opt/owasp-modsecurity-crs/rules/REQUEST-933-APPLICATION-ATTACK-PHP.conf
include /opt/owasp-modsecurity-crs/rules/REQUEST-941-APPLICATION-ATTACK-XSS.conf
include /opt/owasp-modsecurity-crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf
include /opt/owasp-modsecurity-crs/rules/REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION.conf
include /opt/owasp-modsecurity-crs/rules/REQUEST-949-BLOCKING-EVALUATION.conf
include /opt/owasp-modsecurity-crs/rules/RESPONSE-950-DATA-LEAKAGES.conf
include /opt/owasp-modsecurity-crs/rules/RESPONSE-951-DATA-LEAKAGES-SQL.conf
include /opt/owasp-modsecurity-crs/rules/RESPONSE-952-DATA-LEAKAGES-JAVA.conf
include /opt/owasp-modsecurity-crs/rules/RESPONSE-953-DATA-LEAKAGES-PHP.conf
include /opt/owasp-modsecurity-crs/rules/RESPONSE-954-DATA-LEAKAGES-IIS.conf
include /opt/owasp-modsecurity-crs/rules/RESPONSE-959-BLOCKING-EVALUATION.conf
include /opt/owasp-modsecurity-crs/rules/RESPONSE-980-CORRELATION.conf
include /opt/owasp-modsecurity-crs/rules/RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf
EOL

sed -i "s/SecUnicodeMapFile unicode.mapping/SecUnicodeMapFile \/opt\/modsecurity\/unicode.mapping/g" /opt/modsecurity/modsecurity.conf
}

create_configuration_files(){
#Create spoe-modsecurity.conf
cat > /etc/haproxy/spoe-modsecurity.conf << 'EOL'
[modsecurity]
    spoe-agent modsecurity-agent
        messages     check-request
        option       var-prefix  modsec
        timeout      hello       100ms
        timeout      idle        30s
        timeout      processing  1s
        use-backend  spoe-modsecurity
    spoe-message check-request
        args   unique-id method path query req.ver req.hdrs_bin req.body_size req.body
        event  on-frontend-http-request
EOL

#Create haproxy.cfg
cat > /etc/haproxy/haproxy.cfg << 'EOL'
global
    maxconn 20480
    ssl-dh-param-file /etc/haproxy/dhparam.pem
    log 127.0.0.1 local0
    stats socket 127.0.0.1:14567
    tune.ssl.default-dh-param 4096
    server-state-file /tmp/haproxy_server_state
    ssl-default-bind-options ssl-min-ver TLSv1.2
    ssl-default-server-options ssl-min-ver TLSv1.2
    ssl-default-bind-ciphers TLS13-AES-256-GCM-SHA384:TLS13-AES-128-GCM-SHA256:TLS13-CHACHA20-POLY1305-SHA256:EECDH+AESGCM:EECDH+CHACHA20:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256
    ssl-default-server-ciphers TLS13-AES-256-GCM-SHA384:TLS13-AES-128-GCM-SHA256:TLS13-CHACHA20-POLY1305-SHA256:EECDH+AESGCM:EECDH+CHACHA20:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256

defaults
    log global
    mode http
    option httplog
    timeout connect 5s
    timeout client  50s
    timeout server 50s
    # Newly added timeouts
    timeout http-request 10s
    timeout http-keep-alive 2s
    timeout queue 5s
    timeout tunnel 2m
    timeout client-fin 1s
    timeout server-fin 1s
	
frontend myfrontend
    # primary cert is /etc/haproxy/cert/haproxy.pem
    bind *:443 ssl crt /etc/haproxy/cert/haproxy.pem alpn h2,http/1.1
    option			http-keep-alive
    option			forwardfor
    acl https ssl_fc
    filter spoe engine modsecurity config /etc/haproxy/spoe-modsecurity.conf
    http-request deny if { var(txn.modsec.code) -m int gt 0 }
    http-request set-header		X-Forwarded-Proto http if !https
    http-request set-header		X-Forwarded-Proto https if https
    timeout client		30000
    acl ACL1 var(txn.txnhost) -m str -i host.domain.com
    http-request set-var(txn.txnhost) hdr(host)
    use_backend example1 if ACL1
    
backend spoe-modsecurity
      mode tcp
      balance roundrobin
      timeout connect 5s
      timeout server  3m
      server modsec1 127.0.0.1:12345

backend example1
    # a https backend
    http-response set-header Strict-Transport-Security max-age=31536000;\ includeSubDomains;\ preload;
    http-response set-header X-Frame-Options DENY
    http-response set-header X-XSS-Protection 1;mode=block
    http-response set-header X-Content-Type-Options nosniff
    http-response set-header Referrer-Policy same-origin
    http-response set-header Cache-Control private,\ no-cache,\ no-store,\ max-age=0,\ no-transform,\ must-revalidate
    http-response set-header Pragma no-cache
    http-response del-header Server
    http-response del-header X-Powered-By
    server backendhost backendhost.otherdomain.com:443 ssl verify none
EOL

#Create rsyslog haproxy.conf
cat > /etc/rsyslog.d/haproxy.conf << 'EOL'
$ModLoad imudp
$UDPServerRun 514 
$template Haproxy,"%msg%\n"
local0.=info -/var/log/haproxy/haproxy.log;Haproxy
local0.notice -/var/log/haproxy/haproxy_status.log;Haproxy
### keep logs in localhost ##
local0.* ~
EOL

#Create logrotate haproxy
cat > /etc/logrotate.d/haproxy << 'EOL'
/var/log/haproxy/*.log
{
    missingok
    notifempty
    sharedscripts
    rotate 120
	dateext
    dateformat -%Y-%m-%d
    daily
    compress
    postrotate
        systemctl restart rsyslog >/dev/null 2>&1 || true
    endscript
}
EOL

}

create_service_files(){
#Create haproxy service file
cat > /lib/systemd/system/haproxy.service << 'EOL'
[Unit]
Description=HAProxy Load Balancer
After=network.target

[Service]
Environment=LD_LIBRARY_PATH=change_me
EnvironmentFile=-/etc/default/haproxy
EnvironmentFile=-/etc/sysconfig/haproxy
Environment="CONFIG=/etc/haproxy/haproxy.cfg" "PIDFILE=/run/haproxy.pid" "EXTRAOPTS=-S /run/haproxy-master.sock"
ExecStartPre=/usr/local/sbin/haproxy -f $CONFIG -c -q $EXTRAOPTS
ExecStart=/usr/local/sbin/haproxy -Ws -f $CONFIG -p $PIDFILE $EXTRAOPTS
ExecReload=/usr/local/sbin/haproxy -f $CONFIG -c -q $EXTRAOPTS
ExecReload=/bin/kill -USR2 $MAINPID
KillMode=mixed
Restart=always
SuccessExitStatus=143
Type=notify

[Install]
WantedBy=multi-user.target
EOL

sed -i "s/Environment=LD_LIBRARY_PATH=change_me/Environment=LD_LIBRARY_PATH=\/opt\/openssl-${OPENSSLVERSION}\/lib64/g" /lib/systemd/system/haproxy.service

#Create modsecurity service file
cat > /lib/systemd/system/modsecurity.service << 'EOL'
[Unit]
Description=Modsecurity Standalone
After=network.target

[Service]
EnvironmentFile=-/etc/default/modsecurity
EnvironmentFile=-/etc/sysconfig/modsecurity
Environment="CONFIG=/opt/modsecurity/modsecurity.conf" "PIDFILE=/run/modesecurity.pid" "EXTRAOPTS=-d -n 1"
ExecStart=/usr/local/bin/modsecurity $EXTRAOPTS -f $CONFIG
ExecReload=/usr/local/bin/modsecurity $EXTRAOPTS -f $CONFIG
ExecReload=/bin/kill -USR2 $MAINPID
Restart=always
Type=simple

[Install]
WantedBy=multi-user.target
EOL
}

create_dh_param(){
echo "--------------------------"
echo "Creating DH Parameter File"
echo "--------------------------"
echo ""
openssl dhparam -out /etc/haproxy/dhparam.pem 4096
}

enable_services(){
echo "-----------------"
echo "Enabling Services"
echo "-----------------"
echo ""
systemctl enable haproxy
systemctl enable modsecurity
}

final_banner(){
echo ""
echo "------------------------------------------------------------"
echo ""
echo "Upload your TLS certificate to /etc/haproxy/cert/haproxy.pem"
echo ""
echo "Edit /etc/haproxy/haproxy.cfg to your requirements"
echo ""
echo "Then start things running with:"
echo ""
echo "sudo systemctl start modsecurity"
echo "sudo systemctl start haproxy"
echo ""
echo "------------------------------------------------------------"
}

#Begin
print_copy
check_viability

echo "Logging enabled to ${LOG}"

run_and_log check_os_family "Checking OS"
run_and_log install_pre-reqs "Installing Pre-Requisites"
run_and_log create_user "Creating User Account"
run_and_log create_patchfile "Creating PatchFile"
run_and_log download_openssl "Downloading OpenSSL"
run_and_log extract_openssl "Extracting OpenSSL"
run_and_log download_haproxy "Downloading HAProxy"
run_and_log extract_haproxy "Extracting HAProxy"
run_and_log install_openssl "Installing OpenSSL"
run_and_log update_library_links "Updating Library Links"
run_and_log clone_spoa_modsecurity "Cloning spoa-modsecurity"
run_and_log patch_spoa-modsecurity_makefile "Patching Makefile"
run_and_log clone_modsecurity "Cloning Modsecurity"
run_and_log install_modsecurity "Installing Modsecurity"
run_and_log install_spoa-modsecurity "Installing spoa-modsecurity"
run_and_log install_haproxy "Installing HAProxy"
run_and_log clone_owasp_rules "Cloning OWASP Rules"
run_and_log configure_modsecurity "Configuring Modsecurity"
run_and_log create_configuration_files "Creating Configuration Files"
run_and_log create_service_files "Creating Service Files"
run_and_log create_dh_param "Creating DH Param File"
run_and_log enable_services "Enabling Services"
final_banner
