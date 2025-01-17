#!/usr/bin/env bash

#####################################################
# Created by cryptopool.builders for crypto use...
#####################################################

source /etc/functions.sh
source /etc/multipool.conf
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

echo -e " Installing MariaDB 10.4...$COL_RESET"
MARIADB_VERSION='10.4'
sudo debconf-set-selections <<< "maria-db-$MARIADB_VERSION mysql-server/root_password password $DBRootPassword"
sudo debconf-set-selections <<< "maria-db-$MARIADB_VERSION mysql-server/root_password_again password $DBRootPassword"
apt_install mariadb-server mariadb-client
# Pfad zur MySQL-Konfigurationsdatei
CONFIG_FILE="/etc/mysql/my.cnf"

# Backup der Datei erstellen
if [ -f "$CONFIG_FILE" ]; then
    sudo cp "$CONFIG_FILE" "${CONFIG_FILE}.bak"
    echo "Backup erstellt: ${CONFIG_FILE}.bak"
else
    echo "Fehler: $CONFIG_FILE existiert nicht!"
    exit 1
fi

# Prüfen, ob die Sektion [mysqld] existiert
if grep -q "^\[mysqld\]" "$CONFIG_FILE"; then
    echo "[mysqld]-Sektion gefunden."
else
    echo "[mysqld]-Sektion nicht gefunden. Hinzufügen..."
    sudo echo -e "\n[mysqld]" >> "$CONFIG_FILE"
fi

# Einträge für character-set-server und collation-server hinzufügen oder aktualisieren
sudo sed -i '/^\[mysqld\]/a character-set-server = utf8\ncollation-server = utf8_general_ci' "$CONFIG_FILE"

# Änderungen anzeigen
echo "Die folgenden Änderungen wurden vorgenommen:"
sudo grep -A 5 "^\[mysqld\]" "$CONFIG_FILE"

# MySQL-Dienst neu starten
echo "MySQL-Dienst wird neu gestartet..."
sudo systemctl restart mysql && echo "MySQL erfolgreich neu gestartet!" || echo "Fehler beim Neustart von MySQL."
echo -e "$GREEN MariaDB build complete...$COL_RESET"
echo -e " Creating DB users for YiiMP...$COL_RESET"

if [[ ("$wireguard" == "false") ]]; then
  Q1="CREATE DATABASE IF NOT EXISTS ${YiiMPDBName};"
  Q2="GRANT ALL ON ${YiiMPDBName}.* TO '${YiiMPPanelName}'@'localhost' IDENTIFIED BY '$PanelUserDBPassword';"
  Q3="GRANT ALL ON ${YiiMPDBName}.* TO '${StratumDBUser}'@'localhost' IDENTIFIED BY '$StratumUserDBPassword';"
  Q4="FLUSH PRIVILEGES;"
  SQL="${Q1}${Q2}${Q3}${Q4}"
sudo mysql -u root -p"${DBRootPassword}" -e "$SQL"

else
  Q1="CREATE DATABASE IF NOT EXISTS ${YiiMPDBName};"
  Q2="GRANT ALL ON ${YiiMPDBName}.* TO '${YiiMPPanelName}'@'${DBInternalIP}' IDENTIFIED BY '$PanelUserDBPassword';"
  Q3="GRANT ALL ON ${YiiMPDBName}.* TO '${StratumDBUser}'@'${DBInternalIP}' IDENTIFIED BY '$StratumUserDBPassword';"
  Q4="FLUSH PRIVILEGES;"
  SQL="${Q1}${Q2}${Q3}${Q4}"
  sudo mysql -u root -p"${DBRootPassword}" -e "$SQL"
fi

echo -e "$GREEN Database creation complete...$COL_RESET"

echo -e " Creating my.cnf...$COL_RESET"

if [[ ("$wireguard" == "false") ]]; then
  echo '[clienthost1]
user='"${YiiMPPanelName}"'
password='"${PanelUserDBPassword}"'
database='"${YiiMPDBName}"'
host=localhost
[clienthost2]
user='"${StratumDBUser}"'
password='"${StratumUserDBPassword}"'
database='"${YiiMPDBName}"'
host=localhost
[mysql]
user=root
password='"${DBRootPassword}"'
' | sudo -E tee $STORAGE_ROOT/yiimp/.my.cnf >/dev/null 2>&1

else
  echo '[clienthost1]
user='"${YiiMPPanelName}"'
password='"${PanelUserDBPassword}"'
database='"${YiiMPDBName}"'
host='"${DBInternalIP}"'
[clienthost2]
user='"${StratumDBUser}"'
password='"${StratumUserDBPassword}"'
database='"${YiiMPDBName}"'
host='"${DBInternalIP}"'
[mysql]
user=root
password='"${DBRootPassword}"'
' | sudo -E tee $STORAGE_ROOT/yiimp/.my.cnf >/dev/null 2>&1
fi

sudo chmod 0600 $STORAGE_ROOT/yiimp/.my.cnf
echo -e "$GREEN Passwords can be found in $STORAGE_ROOT/yiimp/.my.cnf$COL_RESET"

echo -e " Importing YiiMP Default database values...$COL_RESET"
cd $STORAGE_ROOT/yiimp/yiimp_setup/yiimp/sql
# import sql dump
sudo zcat 2019-11-10-yiimp.sql.gz | sudo mysql -u root -p"${DBRootPassword}" "${YiiMPDBName}"
sudo mysql -u root -p"${DBRootPassword}" "${YiiMPDBName}" --force < 2018-09-22-workers.sql
sudo mysql -u root -p"${DBRootPassword}" "${YiiMPDBName}" --force < 2020-06-03-blocks.sql
sudo mysql -u root -p"${DBRootPassword}" "${YiiMPDBName}" --force < 2022-10-14-shares_solo.sql
sudo mysql -u root -p"${DBRootPassword}" "${YiiMPDBName}" --force < 2022-10-29-blocks_effort.sql
echo -e "$GREEN Database import complete...$COL_RESET"

echo -e " Tweaking MariaDB for better performance...$COL_RESET"
if [[ ("$wireguard" == "false") ]]; then
  sudo sed -i '/max_connections/c\max_connections         = 800' /etc/mysql/my.cnf
  sudo sed -i '/thread_cache_size/c\thread_cache_size       = 512' /etc/mysql/my.cnf
  sudo sed -i '/tmp_table_size/c\tmp_table_size          = 128M' /etc/mysql/my.cnf
  sudo sed -i '/max_heap_table_size/c\max_heap_table_size     = 128M' /etc/mysql/my.cnf
  sudo sed -i '/wait_timeout/c\wait_timeout            = 60' /etc/mysql/my.cnf
  sudo sed -i '/max_allowed_packet/c\max_allowed_packet      = 64M' /etc/mysql/my.cnf
else
  sudo sed -i '/max_connections/c\max_connections         = 800' /etc/mysql/my.cnf
  sudo sed -i '/thread_cache_size/c\thread_cache_size       = 512' /etc/mysql/my.cnf
  sudo sed -i '/tmp_table_size/c\tmp_table_size          = 128M' /etc/mysql/my.cnf
  sudo sed -i '/max_heap_table_size/c\max_heap_table_size     = 128M' /etc/mysql/my.cnf
  sudo sed -i '/wait_timeout/c\wait_timeout            = 60' /etc/mysql/my.cnf
  sudo sed -i '/max_allowed_packet/c\max_allowed_packet      = 64M' /etc/mysql/my.cnf
  sudo sed -i 's/#bind-address=0.0.0.0/bind-address='${DBInternalIP}'/g' /etc/mysql/my.cnf
fi

echo -e "$GREEN Database tweak complete...$COL_RESET"
restart_service mysql
echo -e "$GREEN Database build complete...$COL_RESET"
set +eu +o pipefail
cd $HOME/multipool/yiimp_single
