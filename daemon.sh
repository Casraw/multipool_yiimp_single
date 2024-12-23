#!/usr/bin/env bash

#####################################################
# Created by cryptopool.builders for crypto use...
#####################################################

source /etc/functions.sh
source /etc/multipool.conf
source $STORAGE_ROOT/yiimp/.yiimp.conf
source $HOME/multipool/yiimp_single/.wireguard.install.cnf

set -eu -o pipefail

function print_error {
    read line file <<<$(caller)
    echo "An error occurred in line $line of file $file:" >&2
    sed "${line}q;d" "$file" >&2
}
trap print_error ERR


echo -e " Installing BitCoin PPA...$COL_RESET"
if [ ! -f /etc/apt/sources.list.d/bitcoin.list ]; then
hide_output sudo add-apt-repository -y ppa:bitcoin/bitcoin
fi

echo -e " Installing additional system files required for daemons...$COL_RESET"
hide_output sudo apt-get update
apt_install build-essential libtool autotools-dev \
automake pkg-config libssl-dev libevent-dev bsdmainutils git libboost-all-dev libminiupnpc-dev \
libqt5gui5 libqt5core5a libqt5webkit5-dev libqt5dbus5 qttools5-dev qttools5-dev-tools libprotobuf-dev \
protobuf-compiler libqrencode-dev libzmq3-dev libgmp-dev

sudo mkdir -p $STORAGE_ROOT/yiimp/yiimp_setup/tmp
cd $STORAGE_ROOT/yiimp/yiimp_setup/tmp
echo -e "$GREEN Additional System Files Completed...$COL_RESET"

echo -e " Building Berkeley 4.8, this may take several minutes...$COL_RESET"
sudo mkdir -p $STORAGE_ROOT/berkeley/db4/
hide_output sudo wget 'http://download.oracle.com/berkeley-db/db-4.8.30.NC.tar.gz'
hide_output sudo tar -xzvf db-4.8.30.NC.tar.gz
cd db-4.8.30.NC/build_unix/
hide_output sudo ../dist/configure --enable-cxx --disable-shared --with-pic --prefix=$STORAGE_ROOT/berkeley/db4/
hide_output sudo make install
cd $STORAGE_ROOT/yiimp/yiimp_setup/tmp
sudo rm -r db-4.8.30.NC.tar.gz db-4.8.30.NC
echo -e "$GREEN Berkeley 4.8 Completed...$COL_RESET"

echo -e " Building Berkeley 5.1, this may take several minutes...$COL_RESET"
sudo mkdir -p $STORAGE_ROOT/berkeley/db5/
hide_output sudo wget 'http://download.oracle.com/berkeley-db/db-5.1.29.tar.gz'
hide_output sudo tar -xzvf db-5.1.29.tar.gz
cd db-5.1.29/build_unix/
hide_output sudo ../dist/configure --enable-cxx --disable-shared --with-pic --prefix=$STORAGE_ROOT/berkeley/db5/
hide_output sudo make install
cd $STORAGE_ROOT/yiimp/yiimp_setup/tmp
sudo rm -r db-5.1.29.tar.gz db-5.1.29
echo -e "$GREEN Berkeley 5.1 Completed...$COL_RESET"

echo -e " Building Berkeley 5.3, this may take several minutes...$COL_RESET"
sudo mkdir -p $STORAGE_ROOT/berkeley/db5.3/
hide_output sudo wget 'http://anduin.linuxfromscratch.org/BLFS/bdb/db-5.3.28.tar.gz'
hide_output sudo tar -xzvf db-5.3.28.tar.gz
cd db-5.3.28/build_unix/
hide_output sudo ../dist/configure --enable-cxx --disable-shared --with-pic --prefix=$STORAGE_ROOT/berkeley/db5.3/
hide_output sudo make install
cd $STORAGE_ROOT/yiimp/yiimp_setup/tmp
sudo rm -r db-5.3.28.tar.gz db-5.3.28
echo -e "$GREEN Berkeley 5.3 Completed...$COL_RESET"

if [ "`lsb_release -d | sed 's/.*:\s*//' | sed 's/18\.04\.[0-9]/18.04/' `" == "Ubuntu 18.04 LTS" ]; then
  DISTRO=18
  sudo chmod g-w /etc /etc/default /usr
elif [ "`lsb_release -d | sed 's/.*:\s*//' | sed 's/16\.04\.[0-9]/16.04/' `" == "Ubuntu 16.04 LTS" ]; then
  DISTRO=16
elif [ "`lsb_release -d | sed 's/.*:\s*//' | sed 's/20\.04\.[0-9]/20.04/' `" == "Ubuntu 20.04.6 LTS" ]; then
  DISTRO=20
elif [ "`lsb_release -d | sed 's/.*:\s*//' | sed 's/22\.04\.[0-9]/22.04/' `" == "Ubuntu 22.04 LTS" ]; then
  DISTRO=22
else
  echo "This script is meant for Ubuntu 18.04, 16.04, 20.04 and 22.04!"
  exit
fi

if [ $DISTRO == 18 ] || [ $DISTRO == 16 ]; then
echo -e " Building OpenSSL 1.0.2g, this may take several minutes...$COL_RESET"
cd $STORAGE_ROOT/yiimp/yiimp_setup/tmp
hide_output sudo wget https://www.openssl.org/source/old/1.0.2/openssl-1.0.2g.tar.gz --no-check-certificate
hide_output sudo tar -xf openssl-1.0.2g.tar.gz
cd openssl-1.0.2g
hide_output sudo ./config --prefix=$STORAGE_ROOT/openssl --openssldir=$STORAGE_ROOT/openssl shared zlib
hide_output sudo make
hide_output sudo make install
cd $STORAGE_ROOT/yiimp/yiimp_setup/tmp
sudo rm -r openssl-1.0.2g.tar.gz openssl-1.0.2g
echo -e "$GREEN OpenSSL 1.0.2g Completed...$COL_RESET"
else
  echo -e " Building OpenSSL 1.1.1w, this may take several minutes...$COL_RESET"
  cd $STORAGE_ROOT/yiimp/yiimp_setup/tmp
  hide_output sudo wget https://github.com/openssl/openssl/releases/download/OpenSSL_1_1_1w/openssl-1.1.1w.tar.gz --no-check-certificate
  hide_output sudo tar -xf openssl-1.1.1w.tar.gz
  cd openssl-1.1.1w
  hide_output sudo ./config --prefix=$STORAGE_ROOT/openssl --openssldir=$STORAGE_ROOT/openssl shared zlib
  hide_output sudo make
  hide_output sudo make install
  cd $STORAGE_ROOT/yiimp/yiimp_setup/tmp
  sudo rm -r openssl-1.1.1w.tar.gz openssl-1.1.1w
  echo -e "$GREEN OpenSSL 1.1.1w Completed...$COL_RESET"
fi

echo -e " Building bls-signatures, this may take several minutes...$COL_RESET"
cd $STORAGE_ROOT/yiimp/yiimp_setup/tmp
hide_output sudo wget 'https://github.com/codablock/bls-signatures/archive/v20181101.zip'
hide_output sudo unzip v20181101.zip
cd bls-signatures-20181101
hide_output sudo cmake .
hide_output sudo make install
cd $STORAGE_ROOT/yiimp/yiimp_setup/tmp
sudo rm -r v20181101.zip bls-signatures-20181101
echo -e "$GREEN bls-signatures Completed...$COL_RESET"

echo -e " Building blocknotify.sh...$COL_RESET"
if [[ ("$wireguard" == "true") ]]; then
  source $STORAGE_ROOT/yiimp/.wireguard.conf
  echo '#####################################################
  # Created by cryptopool.builders for crypto use...
  #####################################################
  #!/bin/bash
  blocknotify '""''"${DBInternalIP}"''""':$1 $2 $3' | sudo -E tee /usr/bin/blocknotify.sh >/dev/null 2>&1
  sudo chmod +x /usr/bin/blocknotify.sh
else
  echo '#####################################################
  # Created by cryptopool.builders for crypto use...
  #####################################################
  #!/bin/bash
  blocknotify 127.0.0.1:$1 $2 $3' | sudo -E tee /usr/bin/blocknotify.sh >/dev/null 2>&1
  sudo chmod +x /usr/bin/blocknotify.sh
fi

echo
echo -e "$GREEN Daemon setup completed...$COL_RESET"

set +eu +o pipefail
cd $HOME/multipool/yiimp_single
