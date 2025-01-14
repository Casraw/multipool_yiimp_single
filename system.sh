#!/usr/bin/env bash

#####################################################
# Source https://mailinabox.email/ https://github.com/mail-in-a-box/mailinabox
# Updated by cryptopool.builders for crypto use...
#####################################################

clear
source /etc/functions.sh
STORAGE_ROOT=/home/crypto-data
source $STORAGE_ROOT/yiimp/.yiimp.conf
source $HOME/multipool/yiimp_single/.wireguard.install.cnf

set -eu -o pipefail

function print_error {
    read line file <<<$(caller)
    echo "An error occurred in line $line of file $file:" >&2
    sed "${line}q;d" "$file" >&2
}
trap print_error ERR

if [[ ("$wireguard" == "true") ]]; then
source $STORAGE_ROOT/yiimp/.wireguard.conf
fi

if [[ ("$UsingDomain" == "yes") ]]; then
	echo ${DomainName} | hide_output sudo tee -a /etc/hostname
	sudo hostname "${DomainName}"
fi

# Set timezone
echo -e " Setting TimeZone to UTC...$COL_RESET"
if [ ! -f /etc/timezone ]; then
echo "Setting timezone to UTC."
echo "Etc/UTC" > sudo /etc/timezone
restart_service rsyslog
fi
echo -e "$GREEN Done...$COL_RESET"

# Add repository
echo -e " Adding the required repsoitories...$COL_RESET"
if [ ! -f /usr/bin/add-apt-repository ]; then
echo "Installing add-apt-repository..."
hide_output sudo apt-get -y update
apt_install software-properties-common
fi
echo -e "$GREEN Done...$COL_RESET"

# Distro-Version extrahieren
DISTRO_VERSION=$(lsb_release -rs)

# Basierend auf der Version die Aktionen durchführen
case "$DISTRO_VERSION" in
  18.04|18.04.[0-9])
    DISTRO=18
    hide_output sudo add-apt-repository -y ppa:ondrej/php
    echo -e "$GREEN Done...$COL_RESET"
    hide_output sudo add-apt-repository -y ppa:certbot/certbot
    echo -e "$GREEN Done...$COL_RESET"
    hide_output sudo apt-key adv --recv-keys --keyserver hkp://keyserver.ubuntu.com:80 0xF1656F24C74CD1D8
    sudo add-apt-repository 'deb [arch=amd64] http://mirror.one.com/mariadb/repo/10.4/ubuntu bionic main' >/dev/null 2>&1
    echo -e "$GREEN Done...$COL_RESET"
    apt_install libcurl4-openssl-dev libssh-dev libbrotli-dev libnghttp2-dev
    ;;
  16.04|16.04.[0-9])
    DISTRO=16
    hide_output sudo add-apt-repository -y ppa:ondrej/php
    echo -e "$GREEN Done...$COL_RESET"
    hide_output sudo add-apt-repository -y ppa:certbot/certbot
    echo -e "$GREEN Done...$COL_RESET"
    hide_output sudo apt-key adv --recv-keys --keyserver hkp://keyserver.ubuntu.com:80 0xF1656F24C74CD1D8
    sudo add-apt-repository 'deb [arch=amd64] http://mirror.one.com/mariadb/repo/10.4/ubuntu xenial main' >/dev/null 2>&1
    echo -e "$GREEN Done...$COL_RESET"
    apt_install libcurl4-openssl-dev libssh-dev libbrotli-dev libnghttp2-dev
    ;;
  20.04|20.04.[0-9])
    DISTRO=20
    hide_output sudo add-apt-repository -y ppa:ondrej/php
    echo -e "$GREEN Done...$COL_RESET"
    echo "No APT use snap"
    echo -e "$GREEN Done...$COL_RESET"
    hide_output sudo apt-key adv --recv-keys --keyserver hkp://keyserver.ubuntu.com:80 0xF1656F24C74CD1D8
    sudo add-apt-repository 'deb [arch=amd64] http://mirror.one.com/mariadb/repo/10.4/ubuntu focal main' >/dev/null 2>&1
    echo -e "$GREEN Done...$COL_RESET"
    apt_install libcurl4-openssl-dev libssh-dev libbrotli-dev libnghttp2-dev
    ;;
  22.04|22.04.[0-9])
    DISTRO=22
    hide_output sudo add-apt-repository -y ppa:ondrej/php
    echo -e "$GREEN Done...$COL_RESET"
    hide_output sudo add-apt-repository -y ppa:certbot/certbot
    echo -e "$GREEN Done...$COL_RESET"
    hide_output sudo apt-key adv --recv-keys --keyserver hkp://keyserver.ubuntu.com:80 0xF1656F24C74CD1D8
    sudo add-apt-repository 'deb [arch=amd64] http://mirror.one.com/mariadb/repo/10.6/ubuntu jammy main' >/dev/null 2>&1
    echo -e "$GREEN Done...$COL_RESET"
    apt_install libcurl4-openssl-dev libssh-dev libbrotli-dev libnghttp2-dev
    ;;
  *)
    echo "This script is meant for Ubuntu 18.04, 16.04, 20.04, and 22.04!"
    exit 1
    ;;
esac

echo "Detected Ubuntu version: $DISTRO_VERSION (DISTRO=$DISTRO)"
echo -e "$GREEN Done...$COL_RESET"

# Upgrade System Files
echo -e " Updating system packages...$COL_RESET"
hide_output sudo apt-get update
echo -e "$GREEN Done...$COL_RESET"
echo -e " Upgrading system packages...$COL_RESET"
if [ ! -f /boot/grub/menu.lst ]; then
apt_get_quiet upgrade
else
sudo rm /boot/grub/menu.lst
hide_output sudo update-grub-legacy-ec2 -y
apt_get_quiet upgrade
fi
echo -e "$GREEN Done...$COL_RESET"
echo -e " Running Dist-Upgrade...$COL_RESET"
apt_get_quiet dist-upgrade
echo -e "$GREEN Done...$COL_RESET"
echo -e " Running Autoremove...$COL_RESET"
apt_get_quiet autoremove

echo -e "$GREEN Done...$COL_RESET"
echo -e " Installing Base system packages...$COL_RESET"
apt_install python3 python3-dev python3-pip \
wget curl git sudo coreutils bc \
haveged pollinate unzip \
unattended-upgrades cron ntp fail2ban screen rsyslog

# ### Seed /dev/urandom
echo -e "$GREEN Done...$COL_RESET"
echo -e " Initializing system random number generator...$COL_RESET"
hide_output dd if=/dev/random of=/dev/urandom bs=1 count=32 2> /dev/null
hide_output sudo pollinate -q -r
echo -e "$GREEN Done...$COL_RESET"

echo -e " Initializing UFW Firewall...$COL_RESET"
set +eu +o pipefail
if [ -z "${DISABLE_FIREWALL:-}" ]; then
	# Install `ufw` which provides a simple firewall configuration.
	apt_install ufw

	# Allow incoming connections to SSH.
	ufw_allow ssh;
	ufw_allow http;
	ufw_allow https;
	# ssh might be running on an alternate port. Use sshd -T to dump sshd's #NODOC
	# settings, find the port it is supposedly running on, and open that port #NODOC
	# too. #NODOC
	SSH_PORT=$(sshd -T 2>/dev/null | grep "^port " | sed "s/port //") #NODOC
	if [ ! -z "$SSH_PORT" ]; then
	if [ "$SSH_PORT" != "22" ]; then

	echo Opening alternate SSH port $SSH_PORT. #NODOC
	ufw_allow $SSH_PORT;
	ufw_allow http;
	ufw_allow https;

	fi
	fi

sudo ufw --force enable;
fi #NODOC
set -eu -o pipefail
echo -e "$GREEN Done...$COL_RESET"
echo -e " Installing YiiMP Required system packages...$COL_RESET"
if [ -f /usr/sbin/apache2 ]; then
echo Removing apache...
hide_output apt-get -y purge apache2 apache2-*
hide_output apt-get -y --purge autoremove
fi

hide_output sudo apt-get update

if [[ ("$DISTRO" == "16") ]]; then
apt_install php7.3-fpm php7.3-opcache php7.3-gmp php7.3-fpm php7.3 php7.3-common php7.3-gd \
php7.3-mysql php7.3-imap php7.3-cli php7.3-cgi \
php-pear php-auth-sasl mcrypt imagemagick libruby \
php7.3-curl php7.3-intl php7.3-pspell php7.3-recode php7.3-sqlite3 \
php7.3-tidy php7.3-xmlrpc php7.3-xsl memcached php7.3-memcached php7.3-memcache \
php-imagick php-gettext php7.3-zip php7.3-mbstring \
fail2ban ntpdate python3 python3-dev python3-pip \
curl git sudo coreutils pollinate unzip unattended-upgrades cron \
pwgen libgmp3-dev libmysqlclient-dev libcurl4-gnutls-dev \
libkrb5-dev libldap2-dev libidn11-dev gnutls-dev librtmp-dev \
build-essential libtool autotools-dev automake pkg-config libevent-dev bsdmainutils libssl-dev \
automake cmake gnupg2 ca-certificates lsb-release nginx certbot libsodium-dev \
libnghttp2-dev librtmp-dev libssh2-1 libssh2-1-dev libldap2-dev libidn11-dev libpsl-dev libkrb5-dev
elif [[ ("$DISTRO" == "18") ]]; then
apt_install php7.3-fpm php7.3-opcache php7.3-gmp php7.3-fpm php7.3 php7.3-common php7.3-gd \
php7.3-mysql php7.3-imap php7.3-cli php7.3-cgi \
php-pear php-auth-sasl mcrypt imagemagick libruby \
php7.3-curl php7.3-intl php7.3-pspell php7.3-recode php7.3-sqlite3 \
php7.3-tidy php7.3-xmlrpc php7.3-xsl memcached php7.3-memcached php7.3-memcache \
php-imagick php-gettext php7.3-zip php7.3-mbstring \
fail2ban ntpdate python3 python3-dev python3-pip \
curl git sudo coreutils pollinate unzip unattended-upgrades cron \
pwgen libgmp3-dev libmysqlclient-dev libcurl4-gnutls-dev \
libkrb5-dev libldap2-dev libidn11-dev gnutls-dev librtmp-dev \
build-essential libtool autotools-dev automake pkg-config libevent-dev bsdmainutils libssl-dev \
libpsl-dev libnghttp2-dev automake cmake gnupg2 ca-certificates lsb-release nginx certbot libsodium-dev \
libnghttp2-dev librtmp-dev libssh2-1 libssh2-1-dev libldap2-dev libidn11-dev libpsl-dev libkrb5-dev
elif [[ ("$DISTRO" == "20") ]]; then
  apt_install php7.3-fpm php7.3-opcache php7.3-gmp php7.3-fpm php7.3 php7.3-common php7.3-gd \
  php7.3-mysql php7.3-imap php7.3-cli php7.3-cgi \
  php-pear php7.3-cli php7.3-xml mcrypt imagemagick libruby \
  php7.3-curl php7.3-intl php7.3-pspell php7.3-recode php7.3-sqlite3 \
  php7.3-tidy php7.3-xmlrpc php7.3-xsl memcached php7.3-memcached php7.3-memcache  \
  php7.3-imagick php7.3-gettext php7.3-zip php7.3-mbstring \
  fail2ban chrony python3 python3-dev python3-pip \
  curl git sudo coreutils pollinate unzip unattended-upgrades cron \
  pwgen libgmp-dev default-libmysqlclient-dev libgnutls28-dev \
  libkrb5-dev libldap2-dev libidn11-dev librtmp-dev \
  build-essential libtool autotools-dev automake pkg-config libevent-dev bsdmainutils libssl-dev \
  libpsl-dev libnghttp2-dev automake cmake gnupg2 ca-certificates lsb-release nginx libsodium-dev \
  libnghttp2-dev librtmp-dev libssh2-1 libssh2-1-dev libldap2-dev libidn11-dev libpsl-dev libkrb5-dev
  sudo pear channel-update pear.php.net
  sudo pear install Auth_SASL || true
  sudo snap install --classic certbot
  sudo ln -s /snap/bin/certbot /usr/bin/certbot || true
else
  apt_install php7.3-fpm php7.3-opcache php7.3-gmp php7.3-fpm php7.3 php7.3-common php7.3-gd \
  php7.3-mysql php7.3-imap php7.3-cli php7.3-cgi \
  php-pear php-auth-sasl mcrypt imagemagick libruby \
  php7.3-curl php7.3-intl php7.3-pspell php7.3-recode php7.3-sqlite3 \
  php7.3-tidy php7.3-xmlrpc php7.3-xsl memcached php7.3-memcached php7.3-memcache \
  php-imagick php7.3-gettext php7.3-zip php7.3-mbstring \
  fail2ban chrony python3 python3-dev python3-pip \
  curl git sudo coreutils pollinate unzip unattended-upgrades cron \
  pwgen libgmp-dev default-libmysqlclient-dev libgnutls28-dev \
  libkrb5-dev libldap2-dev libidn11-dev librtmp-dev \
  build-essential libtool autotools-dev automake pkg-config libevent-dev bsdmainutils libssl-dev \
  libpsl-dev libnghttp2-dev automake cmake gnupg2 ca-certificates lsb-release nginx certbot libsodium-dev \
  libnghttp2-dev librtmp-dev libssh2-1 libssh2-1-dev libldap2-dev libidn11-dev libpsl-dev libkrb5-dev
fi

# ### Suppress Upgrade Prompts
# When Ubuntu 20 comes out, we don't want users to be prompted to upgrade,
# because we don't yet support it.
if [ -f /etc/update-manager/release-upgrades ]; then
sudo editconf.py /etc/update-manager/release-upgrades Prompt=never
sudo rm -f /var/lib/ubuntu-release-upgrader/release-upgrade-available
fi

echo -e "$GREEN Done...$COL_RESET"

echo -e " Downloading CryptoPool.builders YiiMP Repo...$COL_RESET"
hide_output sudo git clone ${YiiMPRepo} $STORAGE_ROOT/yiimp/yiimp_setup/yiimp
if [[ ("$CoinPort" == "yes") ]]; then
	cd $STORAGE_ROOT/yiimp/yiimp_setup/yiimp
	sudo git fetch
	sudo git checkout multi-port >/dev/null 2>&1
fi
echo -e "$GREEN System files installed...$COL_RESET"

set +eu +o pipefail
cd $HOME/multipool/yiimp_single
