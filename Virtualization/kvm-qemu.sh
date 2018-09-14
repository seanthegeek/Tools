#!/bin/bash

# https://www.doomedraven.com/2016/05/kvm.html

# 11.09.2018 - code improvement
# 09.09.2018 - ACPI fixes - huge thanks to @2sec4u for your patience and your time/help :P
# 05.09.2018 - libivrt 4.7 and virtlogd
# 19.08.2018 - Intel HAXM notes
# 14.08.2018 - QEMU 3 support tested on ubuntu 18.04
# 03.08.2018 - More anti-anti by Tim Shelton (redsand) @ HAWK (hawk.io) and @http_error_418
# 28.02.2018 - Support for qemu 2.12

# https://github.com/dylanaraps/pure-bash-bible
# https://www.shellcheck.net/

# ACPI tables related
# https://wiki.archlinux.org/index.php/DSDT
# Dump on linux
#   sudo acpidump > acpidump.out
# Dump on Windows
#    https://acpica.org/downloads/binary-tools
#    acpixtract -a acpi/4/acpi.dump

# sudo acpixtract -a acpidump.out
# sudo iasl -d DSDT.dat
# Decompile: iasl -d dsdt.dat
# Recompile: iasl -tc dsdt.dsl

#      strs[0] = "KVMKVMKVM\0\0\0"; /* KVM */
#      strs[1] = "Microsoft Hv"; /* Microsoft Hyper-V or Windows Virtual PC */
#      strs[2] = "VMwareVMware"; /* VMware */
#      strs[3] = "XenVMMXenVMM"; /* Xen */
#      strs[4] = "prl hyperv  "; /* Parallels */
#      strs[5] = "VBoxVBoxVBox"; /* VirtualBox */

#https://www.qemu.org/download/#source or https://download.qemu.org/
qemu_version=3.0.0
# libvirt - https://libvirt.org/sources/
libvirt_version=4.7.0
# virt-manager - https://virt-manager.org/download/sources/virt-manager/
virt_manager_version=1.5.0

# autofilled
OS=""

function usage() {
cat << EndOfHelp
    Usage: $0 <func_name> <args>
    Commands - are case insensitive:
        All - Execs QEMU/SeaBios/KVM/cuckoo
        QEMU - Install QEMU from source
        SeaBios - Install SeaBios and repalce QEMU bios file
        KVM - this will install intel-HAXM if you on Mac
        HAXM - Mac Hardware Accelerated Execution Manager
        Clone - <VM_NAME> <path_to_hdd> <start_from_number> <#vm_to_create> <path_where_to_store>
                * Example Win7x64 /VMs/Win7x64.qcow2 0 5 /var/lib/libvirt/images/
                https://wiki.qemu.org/Documentation/CreateSnapshot
        Libvirt - install libvirt
        Replace_qemu - only fix antivms in QEMU source
        Replace_seabios <path> - only fix antivms in SeaBios source
        Issues - will give you error - solution list
        Cuckoo - add cuckoo user to libvirt(d) group
EndOfHelp
}

function _check_brew() {
    if [ ! -f /usr/local/bin/brew ]; then
        /usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
    fi
}

function install_haxm_mac() {
    _check_brew
    brew cask install intel-haxm
    brew tap jeffreywildman/homebrew-virt-manager
    brew cask install xquartz
    brew install virt-manager virt-viewer
    
    if [ "$SHELL" = "/bin/zsh" ] || [ "$SHELL" = "/usr/bin/zsh" ] ; then
        echo "export LIBVIRT_DEFAULT_URI=qemu:///system" >> "$HOME/.zsh"
    else
        echo "export LIBVIRT_DEFAULT_URI=qemu:///system" >> "$HOME/.bashrc"
    fi
}

function install_libvirt() {
    cd /tmp || return
    if [ -f  libvirt-$libvirt_version.tar.xz ]; then
        rm -r libvirt-$libvirt_version
    else
        wget https://libvirt.org/sources/libvirt-$libvirt_version.tar.xz
    fi
    tar xf libvirt-$libvirt_version.tar.xz
    cd libvirt-$libvirt_version || return 
    if [ "$OS" = "Linux" ]; then
        #sudo apt-get build-dep libvirt
        ./autogen.sh --system --prefix=/usr --localstatedir=/var --sysconfdir=/etc --with-qemu=yes --with-dtrace --with-numad --with-storage-rbd  --disable-nls --with-openvz=no --with-vmware=no --with-phyp=no --with-xenapi=no --with-libxl=no  --with-vbox=no --with-lxc=no --with-vz=no   --with-esx=no --with-hyperv=no --with-yajl=yes --with-secdriver-apparmor=yes --with-apparmor-profiles --with-apparmor-profiles
        make -j"$(getconf _NPROCESSORS_ONLN)"
        checkinstall -D --pkgname=libvirt-$libvirt_version --nodoc --showinstall=no --default 
        #make -j"$(getconf _NPROCESSORS_ONLN)" install
    elif [ "$OS" = "Darwin" ]; then
        ./autogen.sh --system --prefix=/usr/local/ --localstatedir=/var --sysconfdir=/etc --with-qemu=yes --with-dtrace --disable-nls --with-openvz=no --with-vmware=no --with-phyp=no --with-xenapi=no --with-libxl=no  --with-vbox=no --with-lxc=no --with-vz=no   --with-esx=no --with-hyperv=no --with-wireshark-dissector=no --with-yajl=yes
    fi
    # https://wiki.archlinux.org/index.php/Libvirt#Using_polkit
    if [ -f /etc/libvirt/libvirtd.conf ]; then
        path="/etc/libvirt/libvirtd.conf"
    elif [ -f /usr/local/etc/libvirt/libvirtd.conf ]; then
        path="/usr/local/etc/libvirt/libvirtd.conf"
    fi

    sed -i 's/#unix_sock_group/unix_sock_group/g' $path
    sed -i 's/#unix_sock_ro_perms = "0777"/unix_sock_ro_perms = "0770"/g' $path
    sed -i 's/#unix_sock_rw_perms = "0770"/unix_sock_rw_perms = "0770"/g' $path
    sed -i 's/#auth_unix_ro = "none"/auth_unix_ro = "none"/g' $path
    sed -i 's/#auth_unix_rw = "none"/auth_unix_rw = "none"/g' $path

    # https://gitlab.com/apparmor/apparmor/wikis/Libvirt
    echo "[+] Setting AppArmor for libvirt/kvm/qemu"
    sed -i 's/#security_driver = "selinux"/security_driver = "apparmor"/g' /etc/libvirt/qemu.conf
    aa-complain /usr/sbin/libvirtd

    cd /tmp || return
    if [ ! -f v$libvirt_version.zip ]; then
        wget https://github.com/libvirt/libvirt-python/archive/v$libvirt_version.zip
    fi
    unzip v$libvirt_version.zip
    cd libvirt-python* || return 
    python setup.py build
    sudo python setup.py install
}

function install_kvm_linux_apt() {
    sed -i 's/# deb-src/deb-src/g' /etc/apt/sources.list
    sudo apt-get update
    sudo apt-get install build-essential numad python-pip gcc pkg-config cpu-checker glib-2.0 libglib2.0-dev libsdl1.2-dev libaio-dev libcap-dev libattr1-dev libpixman-1-dev libgtk2.0-bin  libxml2-utils systemtap-sdt-dev -y
    sudo apt-get install gtk-update-icon-cache -y
    sudo apt-get install lvm2 -y
    sudo apt-get install debhelper ibusb-1.0-0-dev libxen-dev uuid-dev xfslibs-dev libjpeg-dev libusbredirparser-dev device-tree-compiler texinfo libbluetooth-dev libbrlapi-dev libcap-ng-dev libcurl4-gnutls-dev libfdt-dev gnutls-dev libiscsi-dev libncurses5-dev libnuma-dev libcacard-dev librados-dev librbd-dev libsasl2-dev libseccomp-dev libspice-server-dev -y
    
    # WSL support
    sudo apt-get install gcc make gnutls-bin -y
    # remove old
    sudo apt-get purge libvirt0 libvirt-bin -y
    install_libvirt

    # https://github.com/libvirt/libvirt/commit/e94979e901517af9fdde358d7b7c92cc055dd50c
    groupname=""
    if grep -q -E '^libvirtd:' /etc/group; then
        groupname="libvirtd"
    elif grep -q -E '^libvirt:' /etc/group; then
        groupname="libvirt"
    else
        # create group if missed
        groupname="libvirt"
        sudo groupadd libvirt
    fi
    usermod -G $groupname -a "$(whoami)"

    systemctl enable libvirtd.service
    systemctl restart libvirtd.service
    systemctl enable virtlogd.socket
    systemctl restart virtlogd.socket

    if [ ! -f "v$virt_manager_version.zip" ]; then
        wget https://github.com/virt-manager/virt-manager/archive/v$virt_manager_version.zip
    fi
    unzip "v$virt_manager_version"
    cd "virt-manager-$virt_manager_version" || return
    sudo apt-get install intltool -y
    python setup.py install
    if [ "$SHELL" = "/bin/zsh" ] || [ "$SHELL" = "/usr/bin/zsh" ] ; then
        echo "export LIBVIRT_DEFAULT_URI=qemu:///system" >> "$HOME/.zsh"
    else
        echo "export LIBVIRT_DEFAULT_URI=qemu:///system" >> "$HOME/.bashrc"
    fi
    #reboot me here
    sudo kvm-ok
}


function replace_qemu_clues() {
    echo '[+] Patching QEMU clues'
    if ! sed -i 's/QEMU HARDDISK/<WOOT> HARDDISK/g' qemu*/hw/ide/core.c; then
        echo 'QEMU HARDDISK was not replaced in core.c'; fail=1
    fi
    if ! sed -i 's/QEMU HARDDISK/<WOOT> HARDDISK/g' qemu*/hw/scsi/scsi-disk.c; then
        echo 'QEMU HARDDISK was not replaced in scsi-disk.c'; fail=1
    fi
    if ! sed -i 's/QEMU DVD-ROM/<WOOT> DVD-ROM/g' qemu*/hw/ide/core.c; then
        echo 'QEMU DVD-ROM was not replaced in core.c'; fail=1
    fi
    if ! sed -i 's/QEMU DVD-ROM/<WOOT> DVD-ROM/g' qemu*/hw/ide/atapi.c; then
        echo 'QEMU DVD-ROM was not replaced in atapi.c'; fail=1
    fi
    if ! sed -i 's/s->vendor = g_strdup("QEMU");/s->vendor = g_strdup("<WOOT>");/g' qemu*/hw/scsi/scsi-disk.c; then
        echo 'Vendor string was not replaced in scsi-disk.c'; fail=1
    fi
    if ! sed -i 's/QEMU CD-ROM/<WOOT> CD-ROM/g' qemu*/hw/scsi/scsi-disk.c; then
        echo 'QEMU CD-ROM was not patched in scsi-disk.c'; fail=1
    fi
    if ! sed -i 's/padstr8(buf + 8, 8, "QEMU");/padstr8(buf + 8, 8, "<WOOT>");/g' qemu*/hw/ide/atapi.c; then
        echo 'padstr was not replaced in atapi.c'; fail=1
    fi
    if ! sed -i 's/QEMU MICRODRIVE/<WOOT> MICRODRIVE/g' qemu*/hw/ide/core.c; then
        echo 'QEMU MICRODRIVE was not replaced in core.c'; fail=1
    fi
    if ! sed -i 's/KVMKVMKVM\\0\\0\\0/GenuineIntel/g' qemu*/target/i386/kvm.c; then
        echo 'KVMKVMKVM was not replaced in kvm.c'; fail=1
    fi
	# by @http_error_418
    if  sed -i 's/Microsoft Hv/GenuineIntel/g' qemu*/target/i386/kvm.c; then
        echo 'Microsoft Hv was not replaced in target/i386/kvm.c'; fail=1
    fi
    if ! sed -i 's/"bochs"/"hawks"/g' qemu*/block/bochs.c; then
        echo 'BOCHS was not replaced in block/bochs.c'; fail=1
    fi
    # by Tim Shelton (redsand) @ HAWK (hawk.io)
    if ! sed -i 's/"BOCHS "/"ALASKA"/g' qemu*/include/hw/acpi/aml-build.h; then
        echo 'bochs was not replaced in include/hw/acpi/aml-build.h'; fail=1
    fi
    # by Tim Shelton (redsand) @ HAWK (hawk.io)
    if ! sed -i 's/Bochs Pseudo/Intel RealTime/g' qemu*/roms/ipxe/src/drivers/net/pnic.c; then
        echo 'Bochs Pseudo was not replaced in roms/ipxe/src/drivers/net/pnic.c'; fail=1
    fi
    # by Tim Shelton (redsand) @ HAWK (hawk.io)
    if ! sed -i 's/Bochs\/Plex86/<WOOT>\/FIRM64/g' qemu*/roms/vgabios/vbe.c; then
        echo 'BOCHS was not replaced in roms/vgabios/vbe.c'; fail=1
    fi
}


function replace_seabios_clues() {
    echo "[+] deleting BOCHS APCI tables"
    #rm src/fw/*.hex >/dev/null 2>&1
    echo "[+] Generating SeaBios Kconfig"
    ./scripts/kconfig/merge_config.sh -o . >/dev/null 2>&1
    sed -i 's/CONFIG_ACPI_DSDT=y/CONFIG_ACPI_DSDT=n/g' .config
    sed -i 's/CONFIG_XEN=y/CONFIG_XEN=n/g' .config
    echo "[+] Fixing SeaBios antivms"
    if ! sed -i 's/Bochs/<WOOT>/g' src/config.h; then
        echo 'Bochs was not replaced in src/config.h'; fail=1
    fi
    if ! sed -i 's/BOCHSCPU/<WOOT>/g' src/config.h; then
        echo 'BOCHSCPU was not replaced in src/config.h'; fail=1
    fi
    if ! sed -i 's/"BOCHS "/"<WOOT>"/g' src/config.h; then
        echo 'BOCHS was not replaced in src/config.h'; fail=1
    fi
    if ! sed -i 's/BXPC/<WOOT>/g' src/config.h; then
        echo 'BXPC was not replaced in src/config.h'; fail=1
    fi
    if ! sed -i 's/QEMU0001/<WOOT>/g' src/fw/ssdt-misc.dsl; then
        echo 'QEMU0001 was not replaced in src/fw/ssdt-misc.dsl'; fail=1
    fi
    if ! sed -i 's/QEMU\/Bochs/<WOOT>\/<WOOT>/g' vgasrc/Kconfig; then
        echo 'QEMU\/Bochs was not replaced in vgasrc/Kconfig'; fail=1
    fi
    if ! sed -i 's/qemu /<WOOT> /g' vgasrc/Kconfig; then
        echo 'qemu was not replaced in vgasrc/Kconfig'; fail=1
    fi

    FILES=(
        src/hw/blockcmd.c
        src/fw/paravirt.c
    )
    for file in "${FILES[@]}"; do 
        if ! sed -i 's/"QEMU/"<WOOT>/g' "$file"; then
            echo "QEMU was not replaced in $file"; fail=1
        fi
    done
    if ! sed -i 's/"QEMU"/"<WOOT>"/g' src/hw/blockcmd.c; then
        echo '"QEMU" was not replaced in  src/hw/blockcmd.c'; fail=1
    fi
    FILES=(
        "src/fw/acpi-dsdt.dsl" 
        "src/fw/q35-acpi-dsdt.dsl"
    )
    for file in "${FILES[@]}"; do 
        if ! sed -i 's/"BXPC"/<WOOT>"/g' "$file"; then
            echo "BXPC was not replaced in $file"; fail=1
        fi
        if ! sed -i 's/"BXDSDT"/"<WOOT>"/g' "$file"; then
            echo "BXDSDT was not replaced in $file"; fail=1
        fi
    done
    if ! sed -i 's/"BXPC"/"<WOOT>"/g' "src/fw/ssdt-pcihp.dsl"; then
        echo 'BXPC was not replaced in src/fw/ssdt-pcihp.dsl'; fail=1
    fi
    if ! sed -i 's/"BXDSDT"/"<WOOT>"/g' "src/fw/ssdt-pcihp.dsl"; then
        echo 'BXDSDT was not replaced in src/fw/ssdt-pcihp.dsl'; fail=1
    fi
    if ! sed -i 's/"BXPC"/"<WOOT>"/g' "src/fw/ssdt-proc.dsl"; then
        echo 'BXPC was not replaced in "src/fw/ssdt-proc.dsl"'; fail=1
    fi
    if ! sed -i 's/"BXSSDT"/"<WOOT>"/g' "src/fw/ssdt-proc.dsl"; then
        echo 'BXSSDT was not replaced in src/fw/ssdt-proc.dsl'; fail=1
    fi
    if ! sed -i 's/"BXPC"/"<WOOT>"/g' "src/fw/ssdt-misc.dsl"; then
        echo 'BXPC was not replaced in src/fw/ssdt-misc.dsl'; fail=1
    fi
    if ! sed -i 's/"BXSSDTSU"/"<WOOT>"/g' "src/fw/ssdt-misc.dsl"; then
        echo 'BXDSDT was not replaced in src/fw/ssdt-misc.dsl'; fail=1
    fi
    if ! sed -i 's/"BXSSDTSUSP"/"<WOOT>"/g' src/fw/ssdt-misc.dsl; then
        echo 'BXSSDTSUSP was not replaced in src/fw/ssdt-misc.dsl'; fail=1
    fi
    if ! sed -i 's/"BXSSDT"/"<WOOT>"/g' src/fw/ssdt-proc.dsl; then
        echo 'BXSSDT was not replaced in src/fw/ssdt-proc.dsl'; fail=1
    fi
    if ! sed -i 's/"BXSSDTPCIHP"/"<WOOT>"/g' src/fw/ssdt-pcihp.dsl; then
        echo 'BXPC was not replaced in src/fw/ssdt-pcihp.dsl'; fail=1
    fi
    FILES=(
        src/fw/q35-acpi-dsdt.dsl
        src/fw/acpi-dsdt.dsl
        src/fw/ssdt-misc.dsl
        src/fw/ssdt-proc.dsl
        src/fw/ssdt-pcihp.dsl
        src/config.h
    )
    for file in "${FILES[@]}"; do 
        if ! sed -i 's/"BXPC"/"A M I"/g' "$file"; then
            echo "BXPC was not replaced in $file"; fail=1
        fi
    done
}

function qemu_func() {
    cd /tmp || return 

    echo '[+] Cleaning QEMU old install if exists'
    rm -r /usr/share/qemu >/dev/null 2>&1
    sudo dpkg -r ubuntu-vm-builder python-vm-builder >/dev/null 2>&1
    sudo dpkg -l |grep qemu |cut -d " " -f 3|xargs sudo dpkg --purge --force-all >/dev/null 2>&1

    echo '[+] Downloading QEMU source code'
    if [ ! -f qemu-$qemu_version.tar.xz ]; then 
        wget https://download.qemu.org/qemu-$qemu_version.tar.xz
    fi
    tar xJf qemu-$qemu_version.tar.xz
    fail=0

    if [ "$OS" = "Linux" ]; then
        sudo apt-get install checkinstall openbios-* libssh2-1-dev vde2 liblzo2-dev libghc-gtk3-dev libsnappy-dev libbz2-dev libxml2-dev google-perftools libgoogle-perftools-dev libvde-dev -y
    elif [ "$OS" = "Darwin" ]; then
        _check_brew
        brew install pkg-config libtool jpeg gnutls glib ncurses pixman libpng vde gtk+3 libssh2 libssh2 libvirt snappy libcapn gperftools glib -y
    fi
    # WOOT
    # some checks may be depricated, but keeping them for compatibility with old versions
    if [ $? -eq 0 ]; then
        replace_qemu_clues
        if [ $fail -eq 0 ]; then
            echo '[+] Starting compile it'
            cd qemu-$qemu_version || return
	        # add in future --enable-netmap https://sgros-students.blogspot.com/2016/05/installing-and-testing-netmap.html
            # remove --target-list=i386-softmmu,x86_64-softmmu,i386-linux-user,x86_64-linux-user  if you want all targets
            if [ "$OS" = "Linux" ]; then
                ./configure --prefix=/usr --libexecdir=/usr/lib/qemu --localstatedir=/var --bindir=/usr/bin/ --target-list=i386-softmmu,x86_64-softmmu,i386-linux-user,x86_64-linux-user  --enable-gnutls --enable-docs --enable-gtk --enable-vnc --enable-vnc-sasl --enable-vnc-png --enable-vnc-jpeg --enable-curl --enable-kvm  --enable-linux-aio --enable-cap-ng --enable-vhost-net --enable-vhost-crypto --enable-spice --enable-usb-redir --enable-lzo --enable-snappy --enable-bzip2 --enable-coroutine-pool --enable-libssh2 --enable-libxml2 --enable-tcmalloc --enable-replication --enable-tools --enable-capstone
            elif [ "$OS" = "Darwin" ]; then
                # --enable-vhost-net --enable-vhost-crypto
                ./configure --prefix=/usr --libexecdir=/usr/lib/qemu --localstatedir=/var --bindir=/usr/bin/ --enable-gnutls --enable-docs  --enable-vnc --enable-vnc-sasl --enable-vnc-png --enable-vnc-jpeg --enable-curl --enable-hax --enable-usb-redir --enable-lzo --enable-snappy --enable-bzip2 --enable-coroutine-pool  --enable-libxml2 --enable-tcmalloc --enable-replication --enable-tools --enable-capstone
            fi
            if  [ $? -eq 0 ]; then
                echo '[+] Starting Install it'
                #dpkg -i qemu*.deb
                if [ -f /usr/share/qemu/qemu_logo_no_text.svg ]; then
                    rm /usr/share/qemu/qemu_logo_no_text.svg
                fi
                make -j"$(getconf _NPROCESSORS_ONLN)"
                if [ "$OS" = "Linux" ]; then
                    checkinstall -D --pkgname=qemu-$qemu_version --nodoc --showinstall=no --default
                elif [ "$OS" = "Darwin" ]; then
                    make -j"$(getconf _NPROCESSORS_ONLN)" install
                fi
                # hack for libvirt/virt-manager
                if [ ! -f /usr/bin/qemu-system-x86_64-spice ]; then 
                    ln -s /usr/bin/qemu-system-x86_64 /usr/bin/qemu-system-x86_64-spice
                fi
                if [ ! -f /usr/bin/kvm-spice ]; then 
                    ln -s /usr/bin/qemu-system-x86_64 /usr/bin/kvm-spice
                fi
                if [ ! -f /usr/bin/kvm ]; then 
                    ln -s /usr/bin/qemu-system-x86_64 /usr/bin/kvm
                fi
                if  [ $? -eq 0 ]; then
                    echo '[+] Patched, compiled and installed'
                else
                    echo '[-] Install failed'
                fi
            else
                echo '[-] Compilling failed'
            fi
        else
            echo '[-] Check previous output'
            exit
        fi

    else
        echo '[-] Download QEMU source was not possible'
    fi
    if [ "$OS" = "linux" ]; then
        dpkg --get-selections | grep "qemu" | xargs sudo apt-mark hold
        #sudo apt-mark unhold qemu
    fi
}


function seabios_func() {
    fail=0          
    echo '[+] Installing SeaBios dependencies'
    apt-get install git iasl -y
    if [ -d seabios ]; then
        rm -r seabios
    fi
    if git clone https://github.com/coreboot/seabios.git; then
        cd seabios || return
        if replace_seabios_clues; then
            # sudo make help
            # sudo make menuconfig -> BIOS tables -> disable Include default ACPI DSDT
            if make -j "$(getconf _NPROCESSORS_ONLN)"; then
                echo '[+] Replacing old bios.bin to new out/bios.bin'
                bios=0
                FILES=(
                    "/usr/share/qemu/bios.bin"
                    "/usr/share/qemu/bios-256k.bin" 
                )
                for file in "${FILES[@]}"; do 
                    cp -vf out/bios.bin "$file"
                    bios=1
                done
                if [ $bios -eq 1 ]; then
                    echo '[+] Patched bios.bin placed correctly'
                else
                    echo '[-] Bios patching failed'
                fi
            else
                echo '[-] Bios compilation failed'
            fi
            cd - || return
        else
            echo '[-] check previous errors'
        fi
    else
        echo '[-] Check if git installed or network connection is OK'
    fi
}

function issues(){
cat << EndOfHelp
### Errors and Solutions
    * Error:
        required by /usr/lib/libvirt/storage-file/libvirt_storage_file_fs.so
    * Solution:
        systemctl daemon-reload
        systemctl restart libvirtd libvirt-guests.service

    * Error:
        /libvirt.so.0: version LIBVIRT_PRIVATE_x.x.0' not found (required by /usr/sbin/libvirtd)
    * Solutions:
        1. sudo apt-get purge libvirt0 libvirt-bin
        2. ldd /usr/sbin/libvirtd
        3. ls -lah /usr/lib/libvirt*
            * Make sure what all symlinks pointing to last version

    * Error:
        libvirt: Polkit error : authentication unavailable: no polkit agent available to authenticate action 'org.libvirt.unix.manage'
    * Solutions:
        1. 
            sed -i 's/#unix_sock_group/unix_sock_group/g' /etc/libvirt/libvirtd.conf
            sed -i 's/#unix_sock_ro_perms = "0777"/unix_sock_ro_perms = "0770"/g' /etc/libvirt/libvirtd.conf
            sed -i 's/#unix_sock_rw_perms = "0770"/unix_sock_rw_perms = "0770"/g' /etc/libvirt/libvirtd.conf
            sed -i 's/#auth_unix_ro = "none"/auth_unix_ro = "none"/g' /etc/libvirt/libvirtd.conf
            sed -i 's/#auth_unix_rw = "none"/auth_unix_rw = "none"/g' /etc/libvirt/libvirtd.conf
        2. Add ssh key to $HOME/.ssh/authorized_keys
            virt-manager -c "qemu+ssh://user@host/system?socket=/var/run/libvirt/libvirt-sock"        
    * Slow HDD/Snapshot taking performance?
        Modify
            <driver name='qemu' type='qcow2'/>
        To
            <driver name='qemu' type='qcow2' cache='none' io='native'/>
    * Error:
        error : virPidFileAcquirePath:422 : Failed to acquire pid file '/var/run/libvirtd.pid': Resource temporarily unavailable
    * Solution
        ps aux | grep libvirtd
    
EndOfHelp
}

function cuckoo_user() {
    groupname=""
    if grep -q -E '^libvirtd:' /etc/group; then
        groupname="libvirtd"
    elif grep -q -E '^libvirt:' /etc/group; then
        groupname="libvirt"
    else
        # create group if missed
        groupname="libvirt"
        sudo groupadd libvirt
    fi
    usermod -G $groupname -a cuckoo
}

function cloning() {
    if [ $# -lt 5 ]; then
        echo '[-] You must provide <VM_NAME> <path_to_hdd> <start_from_number> <#vm_to_create> <path_where_to_store>'
        exit 1
    fi
    echo $1
    for i in `seq $3 $4`; do
        worked=1
        # bad macaddress can be generated
        while [ $worked -eq 1 ]; do
            macaddr=$(dd if=/dev/urandom bs=1024 count=1 2>/dev/null|md5sum|sed 's/^\(..\)\(..\)\(..\)\(..\)\(..\)\(..\).*$/\1:\2:\3:\4:\5:\6/') 2>/dev/null
            echo $5/$1_$i.qcow2
            qemu-img create -f qcow2 -b "$2" $5/$1_$i.qcow2 --check all=off
            if virt-clone -n $1_$i -o $1 -m "$macaddr" -f $5/$1_$i.qcow2; then
                worked=0
            fi
        done
        echo "<host mac='$macaddr' name='$FILENAME_$i' ip='192.168.2.$(($i+1))'/>"
    done

    echo "[+] You need to replace path of HDD manually in each new VM, will be scripted in future"

}

# Doesn't work ${$1,,}
COMMAND=$(echo $1|tr '[A-Z]' '[a-z]')

case $COMMAND in
    '-h')
        usage
        exit 0;;
    'issues')
        issues
        exit 0;;
esac

#check if start with root
if [ $EUID -ne 0 ]; then
   echo 'This script must be run as root'
   exit 1
fi

OS="$(uname -s)"

case $COMMAND in
'all')
    qemu_func
    seabios_func
    if [ "$OS" = "Linux" ]; then
        install_kvm_linux_apt
        systemctl daemon-reload
        systemctl restart libvirtd libvirt-guests.service
    elif [ "$OS" = "Darwin" ]; then
        install_haxm_mac
    fi
    cuckoo_user;;
'qemu')
    qemu_func;;
'seabios')
    seabios_func;;
'kvm')
    install_kvm_linux_apt;;
'haxm')
    install_haxm_mac;;
'replace_qemu')
    replace_qemu_clues;;
'libvirt')
    install_libvirt;;
'cuckoo')
    cuckoo_user;;
'clone')
    cloning $2 $3 $4 $5 $6;;
'replace_seabios')
    if [ ! -d "$2" ]; then
        echo "[-] Pass the path to SeaBios folder"
        exit 1
    fi
    cd "$2" || exit 1
    replace_seabios_clues
    cd - || exit 0
    ;;
*)
    usage;;
esac