#!/bin/bash
#
# Script d'installation de Postfix, Dovecot et Rainloop
# Auteur : Hardware <contact@meshup.net>
# Version : 1.0.0
# URLs : https://github.com/hardware/mailserver-autoinstall
#        http://mondedie.fr/viewtopic.php?pid=11746
#
# Nécessite Debian 7 “wheezy” - 32/64 bits minimum. Ainsi que :
# Nginx, PHP, MySQL, OpenSSL (Un serveur LEMP fonctionnel)
#
# Tiré du tutoriel sur mondedie.fr disponible ici:
# http://mondedie.fr/viewtopic.php?id=5302
#
# Installation:
#
# apt-get update && apt-get dist-upgrade
# apt-get install git-core
#
# cd /tmp
# git clone https://github.com/hardware/mailserver-autoinstall.git
# cd mailserver-autoinstall
# chmod a+x install.sh && ./install.sh
#
# Inspiré du script d'installation de rutorrent de Ex_Rat :
# https://bitbucket.org/exrat/install-rutorrent

CSI="\033["
CEND="${CSI}0m"
CRED="${CSI}1;31m"
CGREEN="${CSI}1;32m"
CYELLOW="${CSI}1;33m"
CBLUE="${CSI}1;34m"
CPURPLE="${CSI}1;35m"
CCYAN="${CSI}1;36m"
CBROWN="${CSI}0;33m"

POSTFIXADMIN_VER="2.91"

# ##########################################################################

if [[ $EUID -ne 0 ]]; then
    echo ""
    echo -e "${CRED}/!\ ERREUR: Ce script doit être exécuté en tant que root.${CEND}" 1>&2
    echo ""
    exit 1
fi

# ##########################################################################

smallLoader() {
    echo ""
    echo ""
    echo -ne '[ + + +             ] 3s \r'
    sleep 1
    echo -ne '[ + + + + + +       ] 2s \r'
    sleep 1
    echo -ne '[ + + + + + + + + + ] 1s \r'
    sleep 1
    echo -ne '[ + + + + + + + + + ] Appuyez sur [ENTRÉE] pour continuer... \r'
    echo -ne '\n'

    read
}

checkBin() {
    echo -e "${CRED}/!\ ERREUR: Le programme '$1' est requis pour cette installation.${CEND}"
}

# Vérification des exécutables
command -v dpkg > /dev/null 2>&1 || { echo `checkBin dpkg`    >&2; exit 1; }
command -v apt-get > /dev/null 2>&1 || { echo `checkBin apt-get` >&2; exit 1; }
command -v mysql > /dev/null 2>&1 || { echo `checkBin mysql` >&2; exit 1; }
command -v mysqladmin > /dev/null 2>&1 || { echo `checkBin mysqladmin` >&2; exit 1; }
command -v wget > /dev/null 2>&1 || { echo `checkBin wget` >&2; exit 1; }
command -v tar > /dev/null 2>&1 || { echo `checkBin tar` >&2; exit 1; }
command -v openssl > /dev/null 2>&1 || { echo `checkBin openssl` >&2; exit 1; }
command -v unzip > /dev/null 2>&1 || { echo `checkBin unzip` >&2; exit 1; }

# ##########################################################################

dpkg -s postfix | grep "install ok installed" &> /dev/null

# On vérifie que Postfix n'est pas installé
if [ $? -eq 0 ]; then
    echo ""
    echo -e "${CRED}/!\ ERREUR: Postfix est déjà installé sur le serveur.${CEND}" 1>&2
    echo ""
    # exit 1
fi

dpkg -s dovecot-core | grep "install ok installed" &> /dev/null

# On vérifie que Dovecot n'est pas installé
if [ $? -eq 0 ]; then
    echo ""
    echo -e "${CRED}/!\ ERREUR: Dovecot est déjà installé sur le serveur.${CEND}" 1>&2
    echo ""
    exit 1
fi

dpkg -s opendkim | grep "install ok installed" &> /dev/null

# On vérifie que OpenDKIM n'est pas installé
if [ $? -eq 0 ]; then
    echo ""
    echo -e "${CRED}/!\ ERREUR: OpenDKIM est déjà installé sur le serveur.${CEND}" 1>&2
    echo ""
    exit 1
fi

# ##########################################################################

clear

echo ""
echo -e "${CYELLOW}    Installation automatique d'une serveur de mail avec Postfix et Dovecot${CEND}"
echo ""
echo -e "${CCYAN}
███╗   ███╗ ██████╗ ███╗   ██╗██████╗ ███████╗██████╗ ██╗███████╗   ███████╗██████╗
████╗ ████║██╔═══██╗████╗  ██║██╔══██╗██╔════╝██╔══██╗██║██╔════╝   ██╔════╝██╔══██╗
██╔████╔██║██║   ██║██╔██╗ ██║██║  ██║█████╗  ██║  ██║██║█████╗     █████╗  ██████╔╝
██║╚██╔╝██║██║   ██║██║╚██╗██║██║  ██║██╔══╝  ██║  ██║██║██╔══╝     ██╔══╝  ██╔══██╗
██║ ╚═╝ ██║╚██████╔╝██║ ╚████║██████╔╝███████╗██████╔╝██║███████╗██╗██║     ██║  ██║
╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═════╝ ╚══════╝╚═════╝ ╚═╝╚══════╝╚═╝╚═╝     ╚═╝  ╚═╝

${CEND}"
echo ""

DOMAIN=$(hostname -d 2> /dev/null)   # domain.tld
HOSTNAME=$(hostname -s 2> /dev/null) # hostname
FQDN=$(hostname -f 2> /dev/null)     # hostname.domain.tld

# Récupération de l'adresse IP WAN
WANIP=$(dig +short myip.opendns.com @resolver1.opendns.com)

if [ "$IP" = "" ]; then
    WANIP=$(wget -qO- ipv4.icanhazip.com)
fi

echo -e "${CCYAN}    Configuration du FQDN (Fully qualified domain name) du serveur     ${CEND}"
echo -e "${CCYAN}-----------------------------------------------------------------------${CEND}"
echo ""
echo -e "${CCYAN}[ Votre serveur est actuellement configuré avec les valeurs suivantes ]${CEND}"
echo ""
echo -e "DOMAINE    : ${CGREEN}${DOMAIN}${CEND}"
echo -e "NOM D'HOTE : ${CGREEN}${HOSTNAME}${CEND}"
echo -e "FQDN       : ${CGREEN}${FQDN}${CEND}"
echo -e "IP WAN     : ${CGREEN}${WANIP}${CEND}"
echo ""
echo -e "${CCYAN}-----------------------------------------------------------------------${CEND}"
echo ""

read -p "Souhaitez-vous les modifier ? o/[N] : " REPFQDN

if [[ "$REPFQDN" = "O" ]] || [[ "$REPFQDN" = "o" ]]; then

echo ""
read -p "> Veuillez saisir le nom d'hôte : " HOSTNAME
read -p "> Veuillez saisir le nom de domaine (format: domain.tld) : " DOMAIN

FQDN="${HOSTNAME}.${DOMAIN}"

# Modification du nom d'hôte
echo $HOSTNAME > /etc/hostname

# Modification du FQDN
cat > /etc/hosts <<EOF
127.0.0.1 localhost.localdomain localhost
${WANIP} ${FQDN}               ${HOSTNAME}
EOF

echo ""
echo -e "${CCYAN}-----------------------------------------------------------------------${CEND}"
echo ""
echo -e "${CCYAN}[ Après un redémarrage du serveur, les valeurs seront les suivantes : ]${CEND}"
echo ""
echo -e "DOMAINE    : ${CGREEN}${DOMAIN}${CEND}"
echo -e "NOM D'HOTE : ${CGREEN}${HOSTNAME}${CEND}"
echo -e "FQDN       : ${CGREEN}${FQDN}${CEND}"
echo -e "IP WAN     : ${CGREEN}${WANIP}${CEND}"
echo ""
echo -e "${CCYAN}-----------------------------------------------------------------------${CEND}"
echo ""

smallLoader
clear

fi
#IF REPFQDN

# ##########################################################################

echo ""
echo -e "${CCYAN}-----------------------------${CEND}"
echo -e "${CCYAN}[  SSL Configuration - Cert ]${CEND}"
echo -e "${CCYAN}-----------------------------${CEND}"
echo ""

mkdir -p /etc/nginx/ssl
openssl req -new -x509 -days 3658 -nodes -newkey rsa:2048 -out /etc/nginx/ssl/server.crt -keyout /etc/nginx/ssl/server.key<<EOF
FR




${DOMAIN}
contact@${DOMAIN}
EOF



echo ""
echo -e "${CCYAN}-----------------------------${CEND}"
echo -e "${CCYAN}[  INSTALLATION DE POSTFIX  ]${CEND}"
echo -e "${CCYAN}-----------------------------${CEND}"
echo ""

echo -e "${CGREEN}-> Installation de postfix, postfix-mysql et PHP-IMAP ${CEND}"
echo ""

apt-get install -y postfix postfix-mysql php5-imap

if [ $? -ne 0 ]; then
    echo ""
    echo -e "\n ${CRED}/!\ FATAL: Une erreur est survenue pendant l'installation de Postfix.${CEND}" 1>&2
    echo ""
    exit 1
fi

smallLoader
clear

echo -e "${CCYAN}-------------------------------------------${CEND}"
echo -e "${CCYAN}[  CREATION DE LA BASE DE DONNEE POSTFIX  ]${CEND}"
echo -e "${CCYAN}-------------------------------------------${CEND}"
echo ""

echo ""
echo -e "${CGREEN}------------------------------------------------------------------${CEND}"
read -sp "> Veuillez saisir le mot de passe de l'utilisateur root de MySQL : " MYSQLPASSWD
echo ""
echo -e "${CGREEN}------------------------------------------------------------------${CEND}"
echo ""

# mysqladmin: CREATE DATABASE failed; error: 'Can't create database 'postfix'; database exists'

echo -e "${CGREEN}-> Création de la base de donnée Postfix ${CEND}"
until mysqladmin -uroot -p$MYSQLPASSWD create postfix &> /tmp/mysql-resp.tmp
do
    fgrep -q "database exists" /tmp/mysql-resp.tmp

    # La base de donnée existe déjà ??
    # Si c'est le cas, on arrête l'installation
    if [ $? -eq 0 ]; then
        echo ""
        echo -e "\n ${CRED}/!\ FATAL: La base de donnée Postfix existe déjà.${CEND}" 1>&2
        echo -e "${CRED}Si une installation a déjà été effectuée merci de${CEND}" 1>&2
        echo -e "${CRED}lancer le script de désinstallation puis de re-tenter${CEND}" 1>&2
        echo -e "${CRED}une installation.${CEND}" 1>&2
        echo ""
        exit 1
    fi

    # La base de donnée n'existe pas donc c'est le mot de passe qui n'est pas bon
    echo -e "${CRED}\n /!\ ERREUR: Mot de passe root incorrect \n ${CEND}" 1>&2
    read -sp "> Veuillez re-saisir le mot de passe : " MYSQLPASSWD
    echo -e ""
done

echo -e "${CGREEN}-> Génération du mot de passe de l'utilisateur Postfix ${CEND}"
PFPASSWD=$(strings /dev/urandom | grep -o '[1-9A-NP-Za-np-z]' | head -n 10 | tr -d '\n')
SQLQUERY="CREATE USER 'postfix'@'localhost' IDENTIFIED BY '${PFPASSWD}'; \
          GRANT USAGE ON *.* TO 'postfix'@'localhost'; \
          GRANT ALL PRIVILEGES ON postfix.* TO 'postfix'@'localhost';"

echo -e "${CGREEN}-> Création de l'utilisateur Postfix ${CEND}"
mysql -uroot -p$MYSQLPASSWD "postfix" -e "$SQLQUERY" &> /dev/null

if [ $? -ne 0 ]; then
    echo ""
    echo -e "\n ${CRED}/!\ FATAL: un problème est survenu lors de la création de l'utilisateur 'postfix' dans la BDD.${CEND}" 1>&2
    echo ""
    exit 1
fi

smallLoader
clear

# ##########################################################################

echo -e "${CCYAN}----------------------------------${CEND}"
echo -e "${CCYAN}[  INSTALLATION DE POSTFIXADMIN  ]${CEND}"
echo -e "${CCYAN}----------------------------------${CEND}"
echo ""

echo -e "${CGREEN}-> Téléchargement de PostfixAdmin ${CEND}"
echo ""


if [ ! -d /var/www ]; then
    mkdir -p /var/www
    chown -R www-data:www-data /var/www
fi

cd /var/www
URLPFA="http://downloads.sourceforge.net/project/postfixadmin/postfixadmin/postfixadmin-${POSTFIXADMIN_VER}/postfixadmin-${POSTFIXADMIN_VER}.tar.gz"

until wget $URLPFA
do
    echo -e "${CRED}\n/!\ ERREUR: L'URL de téléchargement de PostfixAdmin est invalide !${CEND}" 1>&2
    echo -e "${CRED}/!\ Merci de rapporter cette erreur ici :${CEND}" 1>&2
    echo -e "${CCYAN}-> https://github.com/hardware/mailserver-autoinstall/issues${CEND} \n" 1>&2
    echo "> Veuillez saisir une autre URL pour que le script puisse télécharger PostfixAdmin : "
    read -p "[URL] : " URLPFA
    echo -e ""
done

# TODO: Vérifier que c'est bien une archive TAR.GZ

echo -e "${CGREEN}-> Décompression du PostfixAdmin ${CEND}"
tar -xzf postfixadmin-$POSTFIXADMIN_VER.tar.gz

echo -e "${CGREEN}-> Création du répertoire /var/www/postfixadmin ${CEND}"
mv postfixadmin-$POSTFIXADMIN_VER postfixadmin
rm -rf postfixadmin-$POSTFIXADMIN_VER.tar.gz

echo -e "${CGREEN}-> Modification des permissions ${CEND}"
chown -R www-data:www-data postfixadmin

PFACONFIG="/var/www/postfixadmin/config.inc.php"

echo -e "${CGREEN}-> Modification du fichier de configuration de PostfixAdmin ${CEND}"
sed -i -e "s|\($CONF\['configured'\].*=\).*|\1 true;|"                 \
       -e "s|\($CONF\['default_language'\] =\).*|\1 'fr';|"            \
       -e "s|\($CONF\['database_type'\].*=\).*|\1 'mysqli';|"          \
       -e "s|\($CONF\['database_host'\].*=\).*|\1 'localhost';|"       \
       -e "s|\($CONF\['database_user'\].*=\).*|\1 'postfix';|"         \
       -e "s|\($CONF\['database_password'\].*=\).*|\1 '${PFPASSWD}';|" \
       -e "s|\($CONF\['database_name'\].*=\).*|\1 'postfix';|"         \
       -e "s|\($CONF\['admin_email'\].*=\).*|\1 'admin@${DOMAIN}';|"   \
       -e "s|\($CONF\['domain_path'\].*=\).*|\1 'YES';|"               \
       -e "s|\($CONF\['domain_in_mailbox'\].*=\).*|\1 'NO';|"          \
       -e "s|\($CONF\['fetchmail'\].*=\).*|\1 'NO';|" $PFACONFIG

echo ""
echo -e "${CCYAN}-----------------------------------------------------------${CEND}"
read -p "> Sous-domaine de PostfixAdmin [Par défaut : postfixadmin] : " PFADOMAIN
read -p "> Chemin du fichier PASSWD [Par défaut : /etc/nginx/passwd] : " PASSWDPATH
echo -e "${CCYAN}-----------------------------------------------------------${CEND}"
echo ""

if [ "$PFADOMAIN" = "" ]; then
    PFADOMAIN="postfixadmin"
fi

if [ "$PASSWDPATH" = "" ]; then
    PASSWDPATH="/etc/nginx/passwd"
fi

echo -e "${CGREEN}-> Ajout du vhost postfixadmin ${CEND}"
cat > /etc/nginx/sites-enabled/postfixadmin.conf <<EOF
server {
  listen 80;
  server_name     ${PFADOMAIN}.${DOMAIN};
  return 301 https://$server_name$request_uri; # enforce https
}

server {
    listen          443 ssl;
    server_name     ${PFADOMAIN}.${DOMAIN};
    root            /var/www/postfixadmin;
    index           index.php;
    charset         utf-8;

	## SSL settings
	ssl_certificate           /etc/nginx/ssl/server.crt;
	ssl_certificate_key       /etc/nginx/ssl/server.key;
	ssl_protocols             TLSv1.2;
	ssl_ciphers               "EECDH+ECDSA+AESGCM:EECDH+aRSA+AESGCM:!aNULL:!eNULL:!LOW:!3DES:!MD5:!EXP:!PSK:!SRP:!DSS:!RC4";
	ssl_prefer_server_ciphers on;
	ssl_session_cache         shared:SSL:10m;
	ssl_session_timeout       10m;
	ssl_ecdh_curve            secp521r1;
	
	add_header Strict-Transport-Security max-age=31536000;

    auth_basic "PostfixAdmin - Connexion";
    auth_basic_user_file ${PASSWDPATH};

    location / {
        try_files \$uri \$uri/ index.php;
    }

    location ~* \.php$ {
        include       /etc/nginx/fastcgi_params;
        fastcgi_pass  unix:/var/run/php5-fpm.sock;
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
    }
}
EOF

echo -e "${CGREEN}-> Redémarrage de PHP-FPM.${CEND}"
service php5-fpm restart
echo -e "${CGREEN}-> Redémarrage de nginx pour prendre en compte le nouveau vhost.${CEND}"
service nginx restart

if [ $? -ne 0 ]; then
    echo ""
    echo -e "${CRED}/!\ ECHEC: un problème est survenu lors du redémarrage de Nginx.${CEND}" 1>&2
    echo -e "${CRED}/!\ Ouvrez une nouvelle session dans un autre terminal et${CEND}" 1>&2
    echo -e "${CRED}/!\ consultez le fichier de log :${CEND} ${CCYAN}/var/log/nginx/errors.log${CEND}" 1>&2
    echo -e "${CRED}/!\ Une fois le problème résolu, appuyez sur [ENTRÉE]...${CEND}" 1>&2
    smallLoader
    echo ""
fi

echo ""
echo -e "${CBROWN}---------------------------------------------------------------------------${CEND}"
echo -e "${CBROWN}Ajoutez la ligne ci-dessous dans le fichier Hosts de votre pc"
echo -e "${CBROWN}si votre nom de domaine n'est pas encore configuré pour"
echo -e "${CBROWN}le sous-domaine${CEND} ${CYELLOW}${PFADOMAIN}.${DOMAIN}${CEND}"
echo ""
echo -e "${CYELLOW}  ${WANIP}     ${PFADOMAIN}.${DOMAIN}${CEND}"
echo ""
echo -e "${CBROWN} - Windows : c:\windows\system32\driver\etc\hosts ${CEND}"
echo -e "${CBROWN} - Linux/MAC : /etc/hosts ${CEND}"
echo ""
echo -e "${CBROWN}Pour finaliser l'installation de PostfixAdmin, allez à l'adresse suivante : ${CEND}"
echo ""
echo -e "${CYELLOW}> http://${PFADOMAIN}.${DOMAIN}/setup.php${CEND}"
echo ""
echo -e "${CBROWN}Veuillez vous assurer que tous les pré-requis ont été validés.${CEND}"
echo -e "${CBROWN}Une fois votre compte administrateur créé, saisissez le hash généré.${CEND}"
echo ""
read -p "> Veuillez saisir le hash généré par le setup : " PFAHASH
echo ""
echo -e "${CBROWN}---------------------------------------------------------------------------${CEND}"
echo ""

# Le hash généré par PFA à une taille de 73 caractères :
# MD5(salt) : SHA1( MD5(salt) : PASSWORD );
#    32     1              40
# Exemple : ffdeb741c58db80d060ddb170af4623a:54e0ac9a55d69c5e53d214c7ad7f1e3df40a3caa
while [ ${#PFAHASH} -ne 73 ]; do
    echo -e "${CRED}\n/!\ HASH invalide !${CEND}" 1>&2
    read -p "> Veuillez saisir de nouveau le hash généré par le setup : " PFAHASH
    echo -e ""
done

echo -e "${CGREEN}-> Ajout du hash dans le fichier config.inc.php ${CEND}"
sed -i "s|\($CONF\['setup_password'\].*=\).*|\1 '${PFAHASH}';|" $PFACONFIG

echo ""
echo -e "${CBROWN}---------------------------------------------------------------------------${CEND}"
echo -e "${CBROWN}Vous pouvez dès à présent vous connecter à PostfixAdmin avec votre compte administrateur.${CEND}"
echo ""
echo -e "${CYELLOW}> http://${PFADOMAIN}.${DOMAIN}/login.php${CEND}"
echo ""
echo -e "${CBROWN}Veuillez ajouter au minimum les éléments ci-dessous :${CEND}"
echo -e "${CBROWN} - Votre domaine :${CEND} ${CGREEN}${DOMAIN}${CEND}"
echo -e "${CBROWN} - Une adresse email :${CEND} ${CGREEN}admin@${DOMAIN}${CEND}"
echo -e "${CBROWN}---------------------------------------------------------------------------${CEND}"
echo ""

echo ""
echo -e "${CRED}-----------------------------------------------------------------------------------${CEND}"
echo -e "${CRED} /!\ N'APPUYEZ PAS SUR ENTREE AVANT D'AVOIR EFFECTUÉ TOUT CE QUI EST AU DESSUS /!\ ${CEND}"
echo -e "${CRED}-----------------------------------------------------------------------------------${CEND}"
echo ""

smallLoader
clear

# ##########################################################################

echo -e "${CCYAN}------------------------------${CEND}"
echo -e "${CCYAN}[  CONFIGURATION DE POSTFIX  ]${CEND}"
echo -e "${CCYAN}------------------------------${CEND}"
echo ""

echo -e "${CGREEN}-> Mise en place du fichier /etc/postfix/master.cf ${CEND}"
sed -i -e "0,/#\(.*smtp\([^s]\).*inet.*n.*smtpd.*\)/s/#\(.*smtp\([^s]\).*inet.*n.*smtpd.*\)/\1/" \
       -e "s/#\(.*submission.*inet.*n.*\)/\1/" \
       -e "s/#\(.*syslog_name=postfix\/submission\)/\1/" \
       -e "s/#\(.*smtpd_tls_security_level=encrypt\)/\1/" \
       -e "0,/#\(.*smtpd_sasl_auth_enable=yes\)/s/#\(.*smtpd_sasl_auth_enable=yes\)/\1/" \
       -e "0,/#\(.*smtpd_client_restrictions=.*\)/s/#\(.*smtpd_client_restrictions=.*\)/\1/" /etc/postfix/master.cf

echo -e "${CGREEN}-> Mise en place du fichier /etc/postfix/main.cf ${CEND}"
cat > /etc/postfix/main.cf <<EOF
smtpd_banner = \$myhostname ESMTP \$mail_name (Debian/GNU)
biff = no
append_dot_mydomain = no
readme_directory = no

smtpd_recipient_restrictions =
     permit_mynetworks,
     permit_sasl_authenticated,
     reject_non_fqdn_recipient,
     reject_unauth_destination,
     reject_unknown_recipient_domain

smtpd_helo_restrictions =
     permit_mynetworks,
     permit_sasl_authenticated,
     reject_invalid_helo_hostname,
     reject_non_fqdn_helo_hostname,
     reject_unknown_helo_hostname

smtpd_client_restrictions =
     permit_mynetworks,
     permit_inet_interfaces,
     permit_sasl_authenticated,
# reject_plaintext_session,
# reject_unauth_pipelining

smtpd_sender_restrictions =
     reject_non_fqdn_sender,
     reject_unknown_sender_domain

smtpd_tls_security_level = may

smtpd_sasl_auth_enable = yes
smtpd_sasl_type = dovecot
smtpd_sasl_path = private/auth
smtpd_sasl_security_options = noanonymous
smtpd_sasl_tls_security_options = \$smtpd_sasl_security_options
smtpd_sasl_local_domain = \$mydomain
smtpd_sasl_authenticated_header = yes

smtpd_tls_auth_only = no
smtpd_tls_cert_file = /etc/ssl/certs/dovecot.pem
smtpd_tls_key_file  = /etc/ssl/private/dovecot.pem

broken_sasl_auth_clients = yes

virtual_uid_maps        = static:5000
virtual_gid_maps        = static:5000
virtual_mailbox_base    = /var/mail
virtual_transport       = lmtp:unix:private/dovecot-lmtp
virtual_mailbox_domains = mysql:/etc/postfix/mysql-virtual-mailbox-domains.cf
virtual_mailbox_maps    = mysql:/etc/postfix/mysql-virtual-mailbox-maps.cf
virtual_alias_maps      = mysql:/etc/postfix/mysql-virtual-alias-maps.cf

myhostname = ${FQDN}
alias_maps = hash:/etc/aliases
alias_database = hash:/etc/aliases
myorigin = /etc/mailname
mydestination = localhost
relayhost =
mynetworks = 127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128
mailbox_command = procmail -a "\$EXTENSION"
mailbox_size_limit = 0
recipient_delimiter = +
inet_interfaces = all
inet_protocols = ipv4
# smtp_address_preference = ipv4
EOF

echo ""
echo -e "${CGREEN}-> Création du fichier mysql-virtual-mailbox-domains.cf ${CEND}"

cat > /etc/postfix/mysql-virtual-mailbox-domains.cf <<EOF
hosts = 127.0.0.1
user = postfix
password = ${PFPASSWD}
dbname = postfix

query = SELECT domain FROM domain WHERE domain='%s' and backupmx = 0 and active = 1
EOF

echo -e "${CGREEN}-> Création du fichier mysql-virtual-mailbox-maps.cf ${CEND}"

cat > /etc/postfix/mysql-virtual-mailbox-maps.cf <<EOF
hosts = 127.0.0.1
user = postfix
password = ${PFPASSWD}
dbname = postfix

query = SELECT maildir FROM mailbox WHERE username='%s' AND active = 1
EOF

echo -e "${CGREEN}-> Création du fichier mysql-virtual-alias-maps.cf ${CEND}"

cat > /etc/postfix/mysql-virtual-alias-maps.cf <<EOF
hosts = 127.0.0.1
user = postfix
password = ${PFPASSWD}
dbname = postfix

query = SELECT goto FROM alias WHERE address='%s' AND active = 1
EOF

smallLoader
clear

echo -e "${CCYAN}-----------------------------${CEND}"
echo -e "${CCYAN}[  INSTALLATION DE DOVECOT  ]${CEND}"
echo -e "${CCYAN}-----------------------------${CEND}"
echo ""

echo -e "${CGREEN}-> Installation de dovecot-core, dovecot-imapd, dovecot-lmtpd et dovecot-mysql ${CEND}"
echo ""
apt-get install -y dovecot-core dovecot-imapd dovecot-lmtpd dovecot-mysql

if [ $? -ne 0 ]; then
    echo ""
    echo -e "\n ${CRED}/!\ FATAL: Une erreur est survenue pendant l'installation de Dovecot.${CEND}" 1>&2
    echo ""
    smallLoader
fi

echo ""
echo -e "${CGREEN}-> Création du conteneur MAILDIR ${CEND}"
mkdir -p /var/mail/vhosts/${DOMAIN}

echo -e "${CGREEN}-> Création d'un nouvel utilisateur nommé vmail avec un UID/GID de 5000 ${CEND}"
groupadd -g 5000 vmail
useradd -g vmail -u 5000 vmail -d /var/mail
chown -R vmail:vmail /var/mail

echo -e "${CGREEN}-> Positionnement des droits sur le répertoire /etc/dovecot ${CEND}"
chown -R vmail:dovecot /etc/dovecot
chmod -R o-rwx /etc/dovecot

echo -e "${CGREEN}-> Déplacement du certificat SSL et de la clé privée dans les répertoires par défaut ${CEND}"
mv /etc/dovecot/dovecot.pem /etc/ssl/certs
mv /etc/dovecot/private/dovecot.pem /etc/ssl/private

echo ""
echo -e "${CGREEN}-> Mise en place du fichier /etc/dovecot/dovecot.conf ${CEND}"
cat > /etc/dovecot/dovecot.conf <<EOF
## Dovecot configuration file

# Enable installed protocols
!include_try /usr/share/dovecot/protocols.d/*.protocol
protocols = imap lmtp

# A space separated list of IP or host addresses where to listen in for
# connections. "*" listens in all IPv4 interfaces. "[::]" listens in all IPv6
# interfaces. Use "*, [::]" for listening both IPv4 and IPv6.
listen = *

# Most of the actual configuration gets included below. The filenames are
# first sorted by their ASCII value and parsed in that order. The 00-prefixes
# in filenames are intended to make it easier to understand the ordering.
!include conf.d/*.conf

# A config file can also tried to be included without giving an error if
# it's not found:
!include_try local.conf
EOF

echo -e "${CGREEN}-> Mise en place du fichier /etc/dovecot/conf.d/10-mail.conf ${CEND}"
cat > /etc/dovecot/conf.d/10-mail.conf <<EOF
## Mailbox locations and namespaces

# Location for users' mailboxes. The default is empty, which means that Dovecot
# tries to find the mailboxes automatically. This won't work if the user
# doesn't yet have any mail, so you should explicitly tell Dovecot the full
# location
mail_location = maildir:/var/mail/vhosts/%d/%n

# If you need to set multiple mailbox locations or want to change default
# namespace settings, you can do it by defining namespace sections.
namespace inbox {
    inbox = yes
}

# Group to enable temporarily for privileged operations. Currently this is
# used only with INBOX when either its initial creation or dotlocking fails.
# Typically this is set to "mail" to give access to /var/mail.
mail_privileged_group = mail
EOF

echo -e "${CGREEN}-> Mise en place du fichier /etc/dovecot/conf.d/10-auth.conf ${CEND}"
cat > /etc/dovecot/conf.d/10-auth.conf <<EOF
## Authentication processes

# Disable LOGIN command and all other plaintext authentications unless
# SSL/TLS is used (LOGINDISABLED capability). Note that if the remote IP
# matches the local IP (ie. you're connecting from the same computer), the
# connection is considered secure and plaintext authentication is allowed.
disable_plaintext_auth = yes

# Space separated list of wanted authentication mechanisms:
# plain login digest-md5 cram-md5 ntlm rpa apop anonymous gssapi otp skey
# gss-spnego
# NOTE: See also disable_plaintext_auth setting.
auth_mechanisms = plain login

#
# Password database is used to verify user's password (and nothing more).
# You can have multiple passdbs and userdbs. This is useful if you want to
# allow both system users (/etc/passwd) and virtual users to login without
# duplicating the system users into virtual database.
#
# <doc/wiki/PasswordDatabase.txt>
#
# User database specifies where mails are located and what user/group IDs
# own them. For single-UID configuration use "static" userdb.
#
# <doc/wiki/UserDatabase.txt>
!include auth-sql.conf.ext
EOF

echo -e "${CGREEN}-> Mise en place du fichier /etc/dovecot/conf.d/auth-sql.conf.ext ${CEND}"
cat > /etc/dovecot/conf.d/auth-sql.conf.ext <<EOF
passdb {
  driver = sql
  args = /etc/dovecot/dovecot-sql.conf.ext
}

userdb {
  driver = static
  args = uid=vmail gid=vmail home=/var/mail/vhosts/%d/%n
}
EOF

echo -e "${CGREEN}-> Mise en place du fichier /etc/dovecot/dovecot-sql.conf.ext ${CEND}"
cat > /etc/dovecot/dovecot-sql.conf.ext <<EOF
# Paramètres de connexion
driver = mysql
connect = host=127.0.0.1 dbname=postfix user=postfix password=${PFPASSWD}

# Permet de définir l'algorithme de hachage.
# Pour plus d'information: http://wiki2.dovecot.org/Authentication/PasswordSchemes
# /!\ ATTENTION : ne pas oublier de modifier le paramètre \$CONF['encrypt'] de PostfixAdmin
default_pass_scheme = MD5-CRYPT

# Requête de récupération du mot de passe du compte utilisateur
password_query = SELECT password FROM mailbox WHERE username = '%u'
EOF

echo -e "${CGREEN}-> Mise en place du fichier /etc/dovecot/conf.d/10-master.conf ${CEND}"
cat > /etc/dovecot/conf.d/10-master.conf <<EOF
service imap-login {
  inet_listener imap {
    port = 0
  }
}

service lmtp {
  # On autorise Postfix à transférer les emails dans le spooler de Dovecot via LMTP
  unix_listener /var/spool/postfix/private/dovecot-lmtp {
      mode = 0600
      user = postfix
      group = postfix
  }
}

service auth {
  # On autorise Postfix à se connecter à Dovecot via LMTP
  unix_listener /var/spool/postfix/private/auth {
      mode = 0666
      user = postfix
      group = postfix
  }

  # On indique à Dovecot les permissions du conteneur local
  unix_listener auth-userdb {
      mode = 0600
      user = vmail
  }

  user = dovecot
}

service auth-worker {
  user = vmail
}
EOF

echo -e "${CGREEN}-> Mise en place du fichier /etc/dovecot/conf.d/10-ssl.conf ${CEND}"
cat > /etc/dovecot/conf.d/10-ssl.conf <<EOF
## SSL settings

# SSL/TLS support: yes, no, required. <doc/wiki/SSL.txt>
ssl = required

# PEM encoded X.509 SSL/TLS certificate and private key. They're opened before
# dropping root privileges, so keep the key file unreadable by anyone but
# root. Included doc/mkcert.sh can be used to easily generate self-signed
# certificate, just make sure to update the domains in dovecot-openssl.cnf
ssl_cert = </etc/ssl/certs/dovecot.pem
ssl_key = </etc/ssl/private/dovecot.pem
EOF

smallLoader
clear

# ##########################################################################

echo -e "${CCYAN}-----------------------------${CEND}"
echo -e "${CCYAN}[  INSTALLATION D'OPENDKIM  ]${CEND}"
echo -e "${CCYAN}-----------------------------${CEND}"
echo ""

echo -e "${CGREEN}-> Installation de opendkim et opendkim-tools ${CEND}"
echo ""
apt-get install -y opendkim opendkim-tools

if [ $? -ne 0 ]; then
    echo ""
    echo -e "\n ${CRED}/!\ FATAL: Une erreur est survenue pendant l'installation d'OpenDKIM.${CEND}" 1>&2
    echo ""
    exit 1
fi

echo ""
echo -e "${CGREEN}-> Mise en place du fichier /etc/opendkim.conf ${CEND}"
cat > /etc/opendkim.conf <<EOF
AutoRestart             Yes
AutoRestartRate         10/1h
UMask                   002
Syslog                  yes
SyslogSuccess           Yes
LogWhy                  Yes

Canonicalization        relaxed/simple

ExternalIgnoreList      refile:/etc/opendkim/TrustedHosts
InternalHosts           refile:/etc/opendkim/TrustedHosts
KeyTable                refile:/etc/opendkim/KeyTable
SigningTable            refile:/etc/opendkim/SigningTable

Mode                    sv
PidFile                 /var/run/opendkim/opendkim.pid
SignatureAlgorithm      rsa-sha256

UserID                  opendkim:opendkim

Socket                  inet:12301@localhost
EOF

echo -e "${CGREEN}-> Mise en place du fichier /etc/default/opendkim ${CEND}"
echo 'SOCKET="inet:12301@localhost"' > /etc/default/opendkim

echo -e "${CGREEN}-> Mise à jour du fichier de configuration de Postfix ${CEND}"
cat >> /etc/postfix/main.cf <<EOF
# Configuration de DKIM
milter_protocol = 2
milter_default_action = accept
smtpd_milters = inet:localhost:12301
non_smtpd_milters = inet:localhost:12301
EOF

echo -e "${CGREEN}-> Création du répertoire /etc/opendkim ${CEND}"
mkdir -p /etc/opendkim/keys

echo -e "${CGREEN}-> Mise en place du fichier /etc/opendkim/TrustedHosts ${CEND}"
cat > /etc/opendkim/TrustedHosts <<EOF
127.0.0.1
localhost
192.168.0.1/24

*.${DOMAIN}
EOF

echo -e "${CGREEN}-> Mise en place du fichier /etc/opendkim/KeyTable ${CEND}"
cat > /etc/opendkim/KeyTable <<EOF
mail._domainkey.${DOMAIN} ${DOMAIN}:mail:/etc/opendkim/keys/${DOMAIN}/mail.private
EOF

echo -e "${CGREEN}-> Mise en place du fichier /etc/opendkim/SigningTable ${CEND}"
cat > /etc/opendkim/SigningTable <<EOF
*@${DOMAIN} mail._domainkey.${DOMAIN}
EOF

echo ""
echo -e "${CPURPLE}-----------------------------------${CEND}"
echo -e "${CPURPLE}[  CREATION DES CLÉS DE SÉCURITÉ  ]${CEND}"
echo -e "${CPURPLE}-----------------------------------${CEND}"
echo ""

cd /etc/opendkim/keys

echo -e "${CGREEN}-> Création du répertoire /etc/opendkim/keys/${DOMAIN} ${CEND}"
mkdir $DOMAIN && cd $DOMAIN

echo -e "${CGREEN}-> Génération des clés de chiffrement ${CEND}"
opendkim-genkey -s mail -d $DOMAIN

echo -e "${CGREEN}-> Modification des permissions des clés ${CEND}"
chown opendkim:opendkim mail.private
chmod 400 mail.private mail.txt

smallLoader
clear

# ##########################################################################

echo -e "${CCYAN}------------------------------${CEND}"
echo -e "${CCYAN}[  INSTALLATION DE RAINLOOP  ]${CEND}"
echo -e "${CCYAN}------------------------------${CEND}"
echo ""

URLRAINLOOP="http://repository.rainloop.net/v2/webmail/rainloop-latest.zip"

until wget $URLRAINLOOP
do
    echo -e "${CRED}\n/!\ ERREUR: L'URL de téléchargement de Rainloop est invalide !${CEND}" 1>&2
    echo -e "${CRED}/!\ Merci de rapporter cette erreur ici :${CEND}" 1>&2
    echo -e "${CCYAN}-> https://github.com/hardware/mailserver-autoinstall/issues${CEND} \n" 1>&2
    echo "> Veuillez saisir une autre URL pour que le script puisse télécharger Rainloop : "
    read -p "[URL] : " URLRAINLOOP
    echo -e ""
done

echo -e "${CGREEN}-> Création du répertoire /var/www/rainloop ${CEND}"
mkdir /var/www/rainloop

echo -e "${CGREEN}-> Décompression de Rainloop dans le répertoire /var/www/rainloop ${CEND}"
unzip rainloop-latest.zip -d /var/www/rainloop > /dev/null

rm -rf rainloop-latest.zip
cd /var/www/rainloop

echo -e "${CGREEN}-> Modification des permissions ${CEND}"
find . -type d -exec chmod 755 {} \;
find . -type f -exec chmod 644 {} \;
chown -R www-data:www-data .

echo ""
echo -e "${CCYAN}-------------------------------------------------${CEND}"
read -p "> Sous-domaine de Rainloop [Par défaut : webmail] : " RAINLOOPDOMAIN
echo -e "${CCYAN}-------------------------------------------------${CEND}"
echo ""

if [ "$RAINLOOPDOMAIN" = "" ]; then
    RAINLOOPDOMAIN="webmail"
fi

echo -e "${CGREEN}-> Ajout du vhost rainloop ${CEND}"
cat > /etc/nginx/sites-enabled/rainloop.conf <<EOF
server {
	listen 			80;
	server_name     ${RAINLOOPDOMAIN}.${DOMAIN};
	return 301 		https://$server_name$request_uri; # enforce https
}

server {
    listen          443 ssl;
    server_name     ${RAINLOOPDOMAIN}.${DOMAIN};
    root            /var/www/rainloop;
    index           index.php;
    charset         utf-8;

	## SSL settings
	ssl_certificate           /etc/nginx/ssl/server.crt;
	ssl_certificate_key       /etc/nginx/ssl/server.key;
	ssl_protocols             TLSv1.2;
	ssl_ciphers               "EECDH+ECDSA+AESGCM:EECDH+aRSA+AESGCM:!aNULL:!eNULL:!LOW:!3DES:!MD5:!EXP:!PSK:!SRP:!DSS:!RC4";
	ssl_prefer_server_ciphers on;
	ssl_session_cache         shared:SSL:10m;
	ssl_session_timeout       10m;
	ssl_ecdh_curve            secp521r1;
	
	add_header Strict-Transport-Security max-age=31536000;

    auth_basic "Webmail - Connexion";
    auth_basic_user_file ${PASSWDPATH};

    location ^~ /data {
        deny all;
    }

    location / {
        try_files \$uri \$uri/ index.php;
    }

    location ~* \.php$ {
        include       /etc/nginx/fastcgi_params;
        fastcgi_pass  unix:/var/run/php5-fpm.sock;
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
    }
}
EOF

echo -e "${CGREEN}-> Redémarrage de PHP-FPM.${CEND}"
service php5-fpm restart
echo -e "${CGREEN}-> Redémarrage de nginx pour prendre en compte le nouveau vhost.${CEND}"
service nginx restart

if [ $? -ne 0 ]; then
    echo ""
    echo -e "${CRED}/!\ ECHEC: un problème est survenu lors du redémarrage de Nginx.${CEND}" 1>&2
    echo -e "${CRED}/!\ Ouvrez une nouvelle session dans un autre terminal et${CEND}" 1>&2
    echo -e "${CRED}/!\ consultez le fichier de log :${CEND} ${CCYAN}/var/log/nginx/errors.log${CEND}" 1>&2
    echo -e "${CRED}/!\ Une fois le problème résolu, appuyez sur [ENTRÉE]...${CEND}" 1>&2
    smallLoader
    echo ""
fi

smallLoader
clear

# ##########################################################################

echo -e "${CCYAN}------------------------------${CEND}"
echo -e "${CCYAN}[  REDÉMARRAGE DES SERVICES  ]${CEND}"
echo -e "${CCYAN}------------------------------${CEND}"
echo ""

service postfix restart

if [ $? -ne 0 ]; then
    echo ""
    echo -e "\n ${CRED}/!\ FATAL: un problème est survenu lors du redémarrage de Postfix.${CEND}" 1>&2
    echo -e "\n ${CRED}/!\ Consultez le fichier de log /var/log/mail.log${CEND}" 1>&2
    echo ""
fi

service dovecot restart

if [ $? -ne 0 ]; then
    echo ""
    echo -e "\n ${CRED}/!\ FATAL: un problème est survenu lors du redémarrage de Dovecot.${CEND}" 1>&2
    echo -e "\n ${CRED}/!\ Consultez le fichier de log /var/log/mail.log${CEND}" 1>&2
    echo ""
fi

service opendkim restart

if [ $? -ne 0 ]; then
    echo ""
    echo -e "\n ${CRED}/!\ FATAL: un problème est survenu lors du redémarrage d'OpenDKIM.${CEND}" 1>&2
    echo ""
fi

echo ""
echo -e "${CCYAN}----------------------------${CEND}"
echo -e "${CCYAN}[  VERIFICATION DES PORTS  ]${CEND}"
echo -e "${CCYAN}----------------------------${CEND}"
echo ""

NBPORT=$(netstat -ptna | grep '0.0.0.0:25\|0.0.0.0:587\|0.0.0.0:993\|127.0.0.1:12301' | wc -l)

# Vérification des ports
if [ $NBPORT -ne 4 ]; then
    echo ""
    echo -e "${CRED}/!\ ERREUR: Nombre de ports invalide !${CEND}" 1>&2
    echo ""
    echo -e "${CRED}POSTFIX: `service postfix  status` !${CEND}"  1>&2
    echo -e "${CRED}DOVECOT: `service dovecot  status` !${CEND}"  1>&2
    echo -e "${CRED}DOVECOT: `service opendkim status` !${CEND}"  1>&2
    echo ""
    exit 1
else
    echo -e "${CGREEN}PORTS : 25, 587, 993, 12301 [OK] ${CEND}"
fi

echo ""
echo -e "${CGREEN}-----------------------------------------${CEND}"
echo -e "${CGREEN}[  INSTALLATION EFFECTUÉE AVEC SUCCÈS ! ]${CEND}"
echo -e "${CGREEN}-----------------------------------------${CEND}"
echo ""

smallLoader
clear

# ##########################################################################

echo -e "${CCYAN}-----------------${CEND}"
echo -e "${CCYAN}[ RÉCAPITULATIF ]${CEND}"
echo -e "${CCYAN}-----------------${CEND}"

echo ""
echo -e "${CBROWN}---------------------------------------------------------------------------${CEND}"
echo -e "${CBROWN}Votre serveur mail est à présent opérationnel, félicitation ! =D${CEND}"
echo ""
echo -e "${CBROWN}Ajoutez la ligne ci-dessous dans le fichier Hosts de votre pc"
echo -e "${CBROWN}si votre nom de domaine n'est pas encore configuré pour"
echo -e "${CBROWN}le sous-domaine${CEND} ${CYELLOW}${RAINLOOPDOMAIN}.${DOMAIN}${CEND}"
echo ""
echo -e "${CYELLOW}  ${WANIP}     ${RAINLOOPDOMAIN}.${DOMAIN}${CEND}"
echo ""
echo -e "${CBROWN}Il ne vous reste plus qu'à configurer Rainloop en ajoutant votre domaine.${CEND}"
echo -e "${CBROWN}Vous pouvez accéder à l'interface d'administration via cette URL :${CEND}"
echo ""
echo -e "${CYELLOW}> http://${RAINLOOPDOMAIN}.${DOMAIN}/?admin${CEND}"
echo ""
echo -e "${CBROWN}Par défaut les identifiants sont :${CEND} ${CGREEN}admin${CEND} et ${CGREEN}12345${CEND}"
echo -e "${CBROWN}Allez voir le tutoriel pour savoir comment rajouter un domaine à Rainloop :${CEND}"
echo ""
echo -e "${CYELLOW}> http://mondedie.fr/viewtopic.php?id=5750${CEND}"
echo ""
echo -e "${CBROWN}Une fois que Rainloop sera correctement configuré, vous pourrez accéder${CEND}"
echo -e "à votre boîte mail via cette URL :${CEND}"
echo ""
echo -e "${CYELLOW}> http://${RAINLOOPDOMAIN}.${DOMAIN}/${CEND}"
echo -e "${CBROWN}---------------------------------------------------------------------------${CEND}"
echo ""

smallLoader

echo -e "${CCYAN}-------------------------------------${CEND}"
echo -e "${CCYAN}[ PARAMÈTRES DE CONNEXION IMAP/SMTP ]${CEND}"
echo -e "${CCYAN}-------------------------------------${CEND}"
echo ""

echo -e "${CGREEN}-> Utilisez les paramètres suivants pour configurer le client mail de votre choix.${CEND}"
echo -e "${CGREEN}-> Le tutoriel suivant explique comment configurer Outlook, MailBird et eM Client.${CEND}"
echo ""

echo -e "${CYELLOW}> http://mondedie.fr/viewtopic.php?pid=11727#p11727${CEND}"

echo ""
echo -e "${CBROWN}---------------------------------------------------------------------------${CEND}"
echo -e "${CBROWN} - Adresse email :${CEND} ${CGREEN}admin@${DOMAIN}${CEND}"
echo -e "${CBROWN} - Nom d'utilisateur IMAP/SMTP :${CEND} ${CGREEN}admin@${DOMAIN}${CEND}"
echo -e "${CBROWN} - Mot de passe IMAP/SMTP :${CEND} ${CGREEN}Celui que vous avez mis dans PostfixAdmin${CEND}"
echo -e "${CBROWN} - Serveur entrant IMAP :${CEND} ${CGREEN}${FQDN}${CEND}"
echo -e "${CBROWN} - Serveur sortant SMTP :${CEND} ${CGREEN}${FQDN}${CEND}"
echo -e "${CBROWN} - Port IMAP :${CEND} ${CGREEN}993${CEND}"
echo -e "${CBROWN} - Port SMTP :${CEND} ${CGREEN}587${CEND}"
echo -e "${CBROWN} - Protocole de chiffrement IMAP :${CEND} ${CGREEN}SSL/TLS${CEND}"
echo -e "${CBROWN} - Protocole de chiffrement SMTP :${CEND} ${CGREEN}STARTTLS${CEND}"
echo -e "${CBROWN}---------------------------------------------------------------------------${CEND}"
echo ""

smallLoader

echo -e "${CCYAN}----------------------------${CEND}"
echo -e "${CCYAN}[ CONFIGURATION DE VOS DNS ]${CEND}"
echo -e "${CCYAN}----------------------------${CEND}"

echo ""
echo -e "${CBROWN}Maintenant ajoutez votre nom d'hôte et vos deux sous-domaines :${CEND}"
echo ""
echo -e "${CCYAN}----------------------------------------------------------${CEND}"
echo -e "${CYELLOW}@                      IN      A         ${WANIP}${CEND}"
echo -e "${CYELLOW}${HOSTNAME}            IN      A         ${WANIP}${CEND}"
echo -e "${CYELLOW}${PFADOMAIN}           IN      CNAME     ${FQDN}.${CEND}"
echo -e "${CYELLOW}${RAINLOOPDOMAIN}      IN      CNAME     ${FQDN}.${CEND}"
echo -e "${CCYAN}----------------------------------------------------------${CEND}"

echo ""
echo -e "${CRED}Vous devez impérativement ajouter un enregistrement de type MX à votre nom de domaine !${CEND}"
echo -e "${CRED}Si cet enregistrement est pas ou mal défini, vous ne reçevrez JAMAIS d'emails.${CEND}"
echo -e "${CRED}Exemple (le point à la fin est IMPORTANT !!) :${CEND}"
echo ""
echo -e "${CCYAN}----------------------------------------------------------${CEND}"
echo -e "${CYELLOW}@    IN    MX    10    ${FQDN}.   ${CEND}"
echo -e "${CCYAN}----------------------------------------------------------${CEND}"

echo ""
echo -e "${CBROWN}Ensuite ajoutez votre enregistrement DKIM :${CEND}"
echo ""
echo -e "${CCYAN}----------------------------------------------------------${CEND}"
cat /etc/opendkim/keys/$DOMAIN/mail.txt
echo -e "${CCYAN}----------------------------------------------------------${CEND}"
echo ""

echo -e "${CBROWN}Et pour finir vos enregistrements SPF :${CEND}"
echo ""
echo -e "${CCYAN}----------------------------------------------------------${CEND}"
echo -e "${CYELLOW}@    IN    TXT    \"v=spf1 a mx ip4:${WANIP} ~all\"     ${CEND}"
echo -e "${CYELLOW}@    IN    SPF    \"v=spf1 a mx ip4:${WANIP} ~all\"     ${CEND}"
echo -e "${CCYAN}----------------------------------------------------------${CEND}"
echo ""

echo -e "${CCYAN}-----------------${CEND}"
echo -e "${CCYAN}[ FIN DU SCRIPT ]${CEND}"
echo -e "${CCYAN}-----------------${CEND}"

exit 0
