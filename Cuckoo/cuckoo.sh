#!/bin/bash
# By @doomedraven - https://twitter.com/D00m3dR4v3n
# /usr/local/lib/python2.7/dist-packages/ratelimit/middleware.py
# try:
#     # Django versions >= 1.9
#     from django.utils.module_loading import import_module
# except ImportError:
#     # Django versions < 1.9
#     from django.utils.importlib import import_module

# If you are using Ubuntu Server 18.04 LTS, remember to have in source list universe and multiverse support

# Static values
# for tor
IFACE_IP="192.168.1.1"
# DB password
PASSWD="SuperPuperCAPESecret"
CUCKOO_ROOT="/opt/sandbox"

yara_version="3.8.1"

mkdir -p $CUCKOO_ROOT

. /etc/os-release
if [[ $ID = ubuntu ]]; then
    read _ UBUNTU_VERSION_NAME <<< "$VERSION"

function usage() {
cat << EndOfHelp
    You need to edit CUCKOO_ROOT, IFACE_IP and PASSWD for correct install

    Usage: $0 <command> <cuckoo_version> <iface_ip>
        Example: $0 cape 192.168.1.1
    Commands - are case insensitive:
        All - Installs dependencies, V2/CAPE, sets supervisor
        Cuckoo - Install V2/CAPE Cuckoo
        Dependencies - Install all dependencies with performance tricks
        Supervisor - Install supervisor config for CAPE; for v2 use cuckoo --help ;)

        Suricata - Install suricata

    Useful links - THEY CAN BE OUTDATED; RTFM!!!
        * https://cuckoo.sh/docs/introduction/index.html
        * https://medium.com/@seifreed/how-to-deploy-cuckoo-sandbox-431a6e65b848
        * https://infosecspeakeasy.org/t/howto-build-a-cuckoo-sandbox/27
    Cuckoo V2 customizations neat howto
        * https://www.adlice.com/cuckoo-sandbox-customization-v2/
EndOfHelp
}

function install_suricata(){
    add-apt-repository -y ppa:oisf/suricata-stable
    apt-get update
    apt-get install -y suricata
    pip install --upgrade suricata-update
    suricata-update update-sources
    suricata-update

    touch /etc/suricata/threshold.config


    if ! grep -q "15 * * * * /usr/local/bin/suricata-update" $(crontab -l); then
        crontab -l | { cat; echo "15 * * * * /usr/local/bin/suricata-update"; } | crontab -
    fi
    if ! grep -q "15 * * * * /usr/bin/suricatasc -c reload-rules" $(crontab -l); then
        crontab -l | { cat; echo "15 * * * * /usr/bin/suricatasc -c reload-rules"; } | crontab -
    fi

    sed -i 's/RUN=yes/RUN=no/g' /etc/default/suricata
    sed -i 's/mpm-algo: ac/mpm-algo: hs/g' /etc/suricata/suricata.yaml
    sed -i 's/mpm-algo: auto/mpm-algo: hs/g' /etc/suricata/suricata.yaml
    sed -i 's/#run-as:/run-as:/g' /etc/suricata/suricata.yaml
    sed -i 's/#  user: suri/   user: cuckoo/g' /etc/suricata/suricata.yaml
    sed -i 's/#  user: suri/   group: cuckoo/g' /etc/suricata/suricata.yaml
    sed -i 's/    depth: 1mb/    depth: 0/g' /etc/suricata/suricata.yaml
    sed -i 's/request-body-limit: 100kb/request-body-limit: 0/g' /etc/suricata/suricata.yaml
    sed -i 's/response-body-limit: 100kb/response-body-limit: 0/g' /etc/suricata/suricata.yaml
    sed -i 's/EXTERNAL_NET: "!$HOME_NET"/EXTERNAL_NET: "ANY"/g' /etc/suricata/suricata.yaml
    # enable eve-log
    python -c "pa = '/etc/suricata/suricata.yaml';q=open(pa, 'rb').read().replace('eve-log:\n      enabled: no\n', 'eve-log:\n      enabled: yes\n');open(pa, 'wb').write(q);"

}

function dependencies() {
    sudo timedatectl set-timezone UTC

    export LANGUAGE=en_US.UTF-8
    export LANG=en_US.UTF-8
    export LC_ALL=en_US.UTF-8

    sudo snap install canonical-livepatch
    #sudo canonical-livepatch enable APITOKEN

    # deps
    apt-get install sqlite3 tmux net-tools checkinstall graphviz git numactl python python-dev python-pip python-m2crypto swig upx-ucl libssl-dev wget unzip p7zip-full geoip-database libgeoip-dev libjpeg-dev mono-utils ssdeep libfuzzy-dev exiftool checkinstall ssdeep uthash-dev libconfig-dev libarchive-dev libtool autoconf automake privoxy software-properties-common wkhtmltopdf xvfb xfonts-100dpi tcpdump libcap2-bin -y
    apt-get install supervisor python-pil subversion python-capstone uwsgi uwsgi-plugin-python -y
    #clamav clamav-daemon clamav-freshclam
    # if broken sudo python -m pip uninstall pip && sudo apt install python-pip --reinstall
    #pip install --upgrade pip
    # /usr/bin/pip
    # from pip import __main__
    # if __name__ == '__main__':
    #     sys.exit(__main__._main())
    pip install requests[security] pyOpenSSL pefile tldextract httpreplay imagehash oletools olefile capstone yara-python PyCrypto voluptuous -U
    # re2
    apt-get install libre2-dev -y
    pip install re2

    sudo pip install matplotlib==2.2.2 numpy==1.15.0 six==1.11.0 statistics==1.0.3.5 lief==0.9.0

    echo "[+] Installing MongoDB"
    sudo apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv 9DA31620334BD75D9DCB49F368818C72E52529D4

    echo "deb [ arch=amd64 ] https://repo.mongodb.org/apt/ubuntu $UBUNTU_VERSION_NAME/mongodb-org/4.0 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb.list

    sudo apt-get update
    sudo apt-get install -y mongodb-org
    pip install pymongo -U

    cat /etc/systemd/system/mongodb.service <<EOF
    [Unit]
    Description=High-performance, schema-free document-oriented database
    After=network.target
    [Service]
    User=root
    #ExecStart=/usr/bin/mongod --quiet --config /etc/mongod.conf
    ExecStart=/usr/bin/numactl --interleave=all /usr/bin/mongod --quiet --bind_ip 0.0.0.0 --port 27017
    [Install]
    WantedBy=multi-user.target
EOF
    systemctl unmask mongodb.service
    systemctl enable mongodb.service
    systemctl restart mongodb.service

    pip install sqlalchemy jinja2 markupsafe bottle django chardet pygal django-ratelimit rarfile jsbeautifier dpkt nose dnspython pytz requests python-magic geoip pillow java-random python-whois git+https://github.com/crackinglandia/pype32.git git+https://github.com/kbandla/pydeep.git flask flask-restful flask-sqlalchemy
    apt install openjdk-8-jdk-headless
    # openjdk-11-jdk-headless
    pip install distorm3 openpyxl git+https://github.com/volatilityfoundation/volatility.git PyCrypto #git+https://github.com/buffer/pyv8
    # Postgresql
    apt-get install postgresql libpq-dev -y
    pip install psycopg2

    #sudo su - postgres
    #psql
    sudo -u postgres -H sh -c "psql -c \"CREATE USER cuckoo WITH PASSWORD '$PASSWD'\"";
    sudo -u postgres -H sh -c "psql -c \"CREATE DATABASE cuckoo\"";
    sudo -u postgres -H sh -c "psql -d \"cuckoo\" -c \"GRANT ALL PRIVILEGES ON DATABASE cuckoo to cuckoo;\""
    #exit

    echo '[+] Installing Yara'
    apt-get install libtool libjansson-dev libmagic1 libmagic-dev -y
    cd /tmp/ || return
    wget "https://github.com/VirusTotal/yara/archive/v$yara_version.zip" && unzip "v$yara_version.zip"
    cd yara* || return
    ./bootstrap.sh
    ./configure --enable-cuckoo --enable-magic --enable-dotnet --enable-profiling
    make -j"$(getconf _NPROCESSORS_ONLN)"
    checkinstall -D --pkgname="yara-$yara_version" --default
    ldconfig
    cd ..
    rm "v$yara_version".zip
    git clone --recursive https://github.com/VirusTotal/yara-python
    cd yara-python || return
    python setup.py build
    python setup.py install

    # elastic as reporting module is incomplate
    #java + elastic
    #add-apt-repository ppa:webupd8team/java -y
    #wget -qO - https://packages.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
    #echo "deb http://packages.elastic.co/elasticsearch/2.x/debian stable main" | sudo tee -a /etc/apt/sources.list.d/elasticsearch-2.x.list
    #apt-get update
    #apt-get install oracle-java8-installer -y
    #apt-get install elasticsearch -y
    #/etc/init.d/elasticsearch start

    sudo apt-get install apparmor-utils -y
    sudo aa-disable /usr/sbin/tcpdump
    # ToDo check if user exits

    groupadd pcap
    usermod -a -G pcap cuckoo
    chgrp pcap /usr/sbin/tcpdump
    setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump

    '''
    cd /tmp/ || return
    git clone https://github.com/rieck/malheur.git
    cd malheur || return
    ./bootstrap
    ./configure --prefix=/usr
    make -j"$(getconf _NPROCESSORS_ONLN)"
    sudo checkinstall -D --pkgname=malheur --default
    dpkg -i malheur_0.6.0-1_amd64.deb
    '''

    install_suricata

    # https://www.torproject.org/docs/debian.html.en
    #echo "deb http://deb.torproject.org/torproject.org bionic main" >> /etc/apt/sources.list
    #echo "deb-src http://deb.torproject.org/torproject.org bionic main" >> /etc/apt/sources.list
    #sudo apt-get install gnupg2 -y
    #gpg2 --recv A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89
    #gpg2 --export A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89 | apt-key add -

    #sudo apt-get update
    #apt install tor deb.torproject.org-keyring -y
    # Tor configuration
    #update-rc.d tor defaults
    #update-rc.d privoxy defaults


    #cat >> /etc/tor/torrc <<EOF
    #TransPort $IFACE_IP:9040
    #DNSPort $IFACE_IP:5353
#EOF

    #Then restart Tor:
 #   service tor restart

    #Edit the Privoxy configuration
    #sudo sed -i 's/R#        forward-socks5t             /     127.0.0.1:9050 ./        forward-socks5t             /     127.0.0.1:9050 ./g' /etc/privoxy/config
    #service privoxy restart

    echo "* soft nofile 1048576" >> /etc/security/limits.conf
    echo "* hard nofile 1048576" >> /etc/security/limits.conf
    echo "root soft nofile 1048576" >> /etc/security/limits.conf
    echo "root hard nofile 1048576" >> /etc/security/limits.conf
    echo "fs.file-max = 100000" >> /etc/sysctl.conf
    echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
    echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf
    echo "net.ipv6.conf.lo.disable_ipv6 = 1" >> /etc/sysctl.conf

    sudo sysctl -p

    ### PDNS
    sudo apt-get install git binutils-dev libldns-dev libpcap-dev libdate-simple-perl libdatetime-perl libdbd-mysql-perl -y
    cd /tmp || return
    git clone git://github.com/gamelinux/passivedns.git
    cd passivedns/ || return
    autoreconf --install
    ./configure
    make -j"$(getconf _NPROCESSORS_ONLN)"
    sudo checkinstall -D --pkgname=passivedns --default

    cd /usr/local/lib/python2.7/dist-packages/volatility || return
    mkdir resources
    cd resources || return
    touch "__init__.py"
    git clone https://github.com/nemequ/lzmat
    cd lzmat || return
    gcc -Wall -fPIC -c lzmat_dec.c
    gcc -shared -Wl,-soname,lzmat_dec.so.1 -o lzmat_dec.so.1.0 lzmat_dec.o
    mv "$(ls)" ..
    cd .. && rm -r lzmat

    cd /tmp || return
    git clone https://github.com/unicorn-engine/unicorn.git
    sudo apt-get install libglib2.0-dev -y
    cd unicorn || return
    ./make.sh
    sudo ./make.sh install
    pip install unicorn Capstone

}

function install_CAPE() {
    cd $CUCKOO_ROOT || return
    git clone https://github.com/ctxis/CAPE/ CAPE

    #chown -R root:cuckoo /usr/var/malheur/
    #chmod -R =rwX,g=rwX,o=X /usr/var/malheur/

    cd /tmp || return
    mkdir work
    git clone https://github.com/herumi/cybozulib
    git clone https://github.com/herumi/msoffice
    cd msoffice || return
    make -j"$(getconf _NPROCESSORS_ONLN)" RELEASE=1
    mkdir -p "$CUCKOO_ROOT/data/msoffice/"
    cp bin/msoffice-crypt.exe "$CUCKOO_ROOT/data/msoffice/"

    # Adapting owner permissions to the cuckoo path folder
    chown cuckoo:cuckoo -R "$CUCKOO_ROOT"

}


function supervisor() {
    #### Cuckoo Start at boot
    cat >> /etc/supervisor/conf.d/cuckoo.conf <<EOF
    [program:cuckoo]
    command=python cuckoo.py
    directory=$CUCKOO_ROOT/CAPE/
    user=cuckoo
    autostart=true
    autorestart=true
    stderr_logfile=/var/log/supervisor/cuckoo.err.log
    stdout_logfile=/var/log/supervisor/cuckoo.out.log

    [program:web]
    command=python manage.py runserver 0.0.0.0:8000
    directory=$CUCKOO_ROOT/CAPE/web
    user=cuckoo
    autostart=true
    autorestart=true
    stderr_logfile=/var/log/supervisor/web.err.log
    stdout_logfile=/var/log/supervisor/web.out.log

    [program:process]
    command=python process.py -p7 auto
    user=cuckoo
    directory=$CUCKOO_ROOT/CAPE/utils
    autostart=true
    autorestart=true
    stderr_logfile=/var/log/supervisor/process.err.log
    stdout_logfile=/var/log/supervisor/process.out.log

    [program:rooter]
    command=python rooter.py
    directory=$CUCKOO_ROOT/CAPE/utils
    user=root
    autostart=true
    autorestart=true
    stderr_logfile=/var/log/supervisor/router.err.log
    stdout_logfile=/var/log/supervisor/router.out.log
EOF

    sudo service supervisor start

    # sudo systemctl enable tor.service
    #sudo systemctl enable elasticsearch.service
    sudo systemctl enable supervisor.service
    sudo systemctl enable supervisor
    sudo systemctl start supervisor

    #supervisord -c /etc/supervisor/supervisord.conf
    supervisorctl -c /etc/supervisor/supervisord.conf reload

    supervisorctl reread
    supervisorctl update
    # msoffice decrypt encrypted files

}



# Doesn't work ${$1,,}
COMMAND=$(echo "$1"|tr "[A-Z]" "[a-z]")

case $COMMAND in
    '-h')
        usage
        exit 0;;
esac


if [ $# -eq 3 ]; then
    cuckoo_version=$2
    IFACE_IP=$3
elif [ $# -eq 2 ]; then
    cuckoo_version=$2
elif [ $# -eq 0 ]; then
    echo "[-] check --help"
    exit 1
fi

cuckoo_version=$(echo "$cuckoo_version"|tr "[A-Z]" "[a-z]")


#check if start with root
if [ "$EUID" -ne 0 ]; then
   echo 'This script must be run as root'
   exit 1
fi

OS="$(uname -s)"

case "$COMMAND" in
'all')
    dependencies
    if [ "$cuckoo_version" = "v2" ]; then
        pip install cuckoo
    else
        install_CAPE
    fi
    supervisor
    ;;
'supervisor')
    supervisor;;
'cuckoo')
    if [ "$cuckoo_version" = "v2" ]; then
        pip install cuckoo
        print "[*] run cuckoo under cuckoo user, NEVER RUN IT AS ROOT!"
    else
        install_CAPE
    fi;;
'dependencies')
    dependencies;;
'suricata')
    install_suricata;;
*)
    usage;;
esac