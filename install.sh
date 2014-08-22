#!/bin/bash
#
# Script d'installation de Postfix, Dovecot et Rainloop
# Auteur : Hardware <contact@meshup.net>
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

checkBin() {
    echo -e "${CRED}/!\ ERREUR: Le programme '$1' est requis pour cette installation."
}

# Vérification des exécutables
command -v dpkg > /dev/null 2>&1 || { echo `checkBin dpkg`    >&2; exit 1; }
command -v apt-get > /dev/null 2>&1 || { echo `checkBin apt-get` >&2; exit 1; }
command -v mysql > /dev/null 2>&1 || { echo `checkBin mysql` >&2; exit 1; }
command -v mysqladmin > /dev/null 2>&1 || { echo `checkBin mysqladmin` >&2; exit 1; }
command -v wget > /dev/null 2>&1 || { echo `checkBin wget` >&2; exit 1; }
command -v tar > /dev/null 2>&1 || { echo `checkBin tar` >&2; exit 1; }
command -v openssl > /dev/null 2>&1 || { echo `checkBin openssl` >&2; exit 1; }

# ##########################################################################

dpkg -s postfix | grep "install ok installed" 2> /dev/null

# On vérifie que Postfix n'est pas installé
if [ $? -eq 0 ]; then
    echo ""
    echo -e "${CRED}/!\ ERREUR: Postfix est déjà installé sur le serveur.${CEND}" 1>&2
    echo ""
    # exit 1
fi

dpkg -s dovecot-core | grep "install ok installed" 2> /dev/null

# On vérifie que Dovecot n'est pas installé
if [ $? -eq 0 ]; then
    echo ""
    echo -e "${CRED}/!\ ERREUR: Dovecot est déjà installé sur le serveur.${CEND}" 1>&2
    echo ""
    exit 1
fi

dpkg -s opendkim | grep "install ok installed" 2> /dev/null

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
echo -e "${CYELLOW}
                                      |          |_)         _|
            __ \`__ \   _ \  __ \   _\` |  _ \  _\` | |  _ \   |    __|
            |   |   | (   | |   | (   |  __/ (   | |  __/   __| |
           _|  _|  _|\___/ _|  _|\__,_|\___|\__,_|_|\___|_)_|  _|

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

fi
#IF REPFQDN

# ##########################################################################

echo ""
echo -e "${CPURPLE}-----------------------------${CEND}"
echo -e "${CPURPLE}[  INSTALLATION DE POSTFIX  ]${CEND}"
echo -e "${CPURPLE}-----------------------------${CEND}"
echo ""

echo -e "${CGREEN}-> Installation de postfix et postfix-mysql ${CEND}"
apt-get install -y postfix postfix-mysql

if [ $? -ne 0 ]; then
    echo ""
    echo -e "\n ${CRED}/!\ Une erreur est survenue pendant l'installation des paquets postfix et postfix-mysql.${CEND}" 1>&2
    echo ""
    exit 1
fi


echo ""
echo -e "${CCYAN}------------------------------------------------------------------${CEND}"
read -sp "> Veuillez saisir le mot de passe de l'utilisateur root de MySQL : " MYSQLPASSWD
echo ""
echo -e "${CCYAN}------------------------------------------------------------------${CEND}"
echo ""

echo -e "${CGREEN}-> Création de la base de donnée Postfix ${CEND}"
until mysqladmin -uroot -p$MYSQLPASSWD create postfix 2> /dev/null
do
    echo -e "${CRED}\n /!\ ERREUR: Mot de passe root incorrect \n ${CEND}" 1>&2
    read -sp "> Veuillez re-saisir le mot de passe : " MYSQLPASSWD
    echo -e ""
done

echo -e "${CGREEN}-> Génération du mot de passe de l'utilisateur Postfix ${CEND}"
PFPASSWD=$(strings /dev/urandom | grep -o '[1-9A-NP-Za-np-z]' | head -n 10 | tr -d '\n')
SQLQUERY="CREATE USER 'postfix'@'localhost' IDENTIFIED BY '${PFPASSWD}'; \
          GRANT USAGE ON *.* TO 'postfix'@'localhost' IDENTIFIED BY '${PFPASSWD}'; \
          GRANT ALL PRIVILEGES ON postfix.* TO 'postfix'@'localhost';"

echo -e "${CGREEN}-> Création de l'utilisateur Postfix ${CEND}"
mysql -uroot -p$MYSQLPASSWD "postfix" -e "$SQLQUERY"

if [ $? -ne 0 ]; then
    echo ""
    echo -e "\n ${CRED}/!\ ECHEC: un problème est survenue lors de la création de l'utilisateur 'postfix'.${CEND}" 1>&2
    echo ""
fi

# ##########################################################################

echo ""
echo -e "${CPURPLE}----------------------------------${CEND}"
echo -e "${CPURPLE}[  INSTALLATION DE POSTFIXADMIN  ]${CEND}"
echo -e "${CPURPLE}----------------------------------${CEND}"
echo ""

echo -e "${CGREEN}-> Téléchargement de PostfixAdmin ${CEND}"
cd /var/www

URLPFA="http://downloads.sourceforge.net/project/postfixadmin/postfixadmin/postfixadmin-${POSTFIXADMIN_VER}/postfixadmin-${POSTFIXADMIN_VER}.tar.gz"

until wget $URLPFA
do
    echo -e "${CRED}\n/!\ ERREUR: URL de téléchargement invalide !${CEND}" 1>&2
    echo -e "${CRED}/!\ Merci de rapporter cette erreur ici :${CEND}" 1>&2
    echo -e "${CCYAN}-> https://github.com/hardware/mailserver-autoinstall/issues${CEND} \n" 1>&2
    echo "> Veuillez saisir une autre URL pour que le script puisse télécharger PostfixAdmin : "
    read -p "[URL]: " URLPFA
    echo -e ""
done

tar -xzf postfixadmin-$POSTFIXADMIN_VER.tar.gz
mv postfixadmin-$POSTFIXADMIN_VER postfixadmin
rm -rf postfixadmin-$POSTFIXADMIN_VER.tar.gz
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
   root            /var/www/postfixadmin;
   index           index.php;
   charset         utf-8;

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

echo -e "${CGREEN}-> Redémarrage de nginx pour prendre en compte le nouveau vhost.${CEND}"
service nginx restart

if [ $? -ne 0 ]; then
    echo ""
    echo -e "\n ${CRED}/!\ ECHEC: un problème est survenue lors du redémarrage de nginx.${CEND}" 1>&2
    echo -e "\n ${CRED}/!\ Consultez le fichier de log /var/log/nginx/errors.log.${CEND}" 1>&2
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
echo -e "${CBROWN} - Votre domaine : ${CEND}${CGREEN}${DOMAIN}${CEND}"
echo -e "${CBROWN} - Une adresse email : ${CEND}${CGREEN}admin@${DOMAIN}${CEND}"
echo -e "${CBROWN}---------------------------------------------------------------------------${CEND}"
echo ""

echo ""
echo -e "${CRED}------------------------------------------------------------------------------------------${CEND}"
echo -e "${CRED} /!\ N'APPUYEZ PAS SUR ENTREE AVANT D'AVOIR EFFECTUÉ TOUT CE QUI EST AU DESSUS /!\ ${CEND}"
echo -e "${CRED}------------------------------------------------------------------------------------------${CEND}"
echo ""

echo -e "${CCYAN}Appuyez sur [ENTREE] pour continuer...${CEND}"
read

echo ""
echo -e "${CCYAN}----------------------------------${CEND}"
echo -e "${CCYAN}Reprise du script dans 10 secondes${CEND}"
echo -e "${CCYAN}----------------------------------${CEND}"
echo ""
echo -ne '[                  ] 10s \r'
sleep 1
echo -ne '[+                 ] 9s \r'
sleep 1
echo -ne '[+ +               ] 8s \r'
sleep 1
echo -ne '[+ + +             ] 7s \r'
sleep 1
echo -ne '[+ + + +           ] 6s \r'
sleep 1
echo -ne '[+ + + + +         ] 5s \r'
sleep 1
echo -ne '[+ + + + + +       ] 4s \r'
sleep 1
echo -ne '[+ + + + + + +     ] 3s \r'
sleep 1
echo -ne '[+ + + + + + + +   ] 2s \r'
sleep 1
echo -ne '[+ + + + + + + + + ] 1s \r'
sleep 1
echo -ne '[+ + + + + + + + + +] Reprise... \r'
echo -ne '\n'

# ##########################################################################

echo ""
echo -e "${CPURPLE}------------------------------${CEND}"
echo -e "${CPURPLE}[  CONFIGURATION DE POSTFIX  ]${CEND}"
echo -e "${CPURPLE}------------------------------${CEND}"
echo ""

echo -e "${CGREEN}-> Mise en place du fichier /etc/postfix/master.cf ${CEND}"
cat >> /etc/postfix/master.cf <<EOF
submission inet n       -       -       -       -       smtpd
   -o syslog_name=postfix/submission
   -o smtpd_tls_security_level=encrypt
   -o smtpd_sasl_auth_enable=yes
   -o smtpd_client_restrictions=permit_sasl_authenticated,reject
EOF

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
     reject_invalid_helo_hostname,
     reject_non_fqdn_helo_hostname,
     reject_unknown_helo_hostname

smtpd_client_restrictions =
     permit_mynetworks,
     permit_inet_interfaces,
     permit_sasl_authenticated,
     reject_plaintext_session,
     reject_unauth_pipelining

smtpd_sender_restrictions =
     reject_non_fqdn_sender,
     reject_unknown_sender_domain

smtpd_tls_security_level=encrypt

smtpd_sasl_auth_enable = yes
smtpd_sasl_type = dovecot
smtpd_sasl_path = private/auth
smtpd_sasl_security_options = noanonymous
smtpd_sasl_tls_security_options = \$smtpd_sasl_security_options
smtpd_sasl_local_domain = \$mydomain
smtpd_sasl_authenticated_header = yes

smtpd_tls_auth_only = yes
smtpd_tls_cert_file = /etc/ssl/certs/server.crt
smtpd_tls_key_file  = /etc/ssl/private/server.key

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
inet_protocols = ipv4, ipv6
smtp_address_preference = any
EOF

SSLOPTS="req -new -x509 -days 1095 -nodes -newkey rsa:4096"

echo -e "${CGREEN}-> Création du certificat SSL ${CEND}"
echo ""
openssl $SSLOPTS -out /etc/ssl/certs/server.crt -keyout /etc/ssl/private/server.key <<EOF
FR
France
Paris
UNKNOWN
UNKNOWN
${FQDN}
admin@${DOMAIN}
EOF

echo -e "\n"
echo -e "\n"
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

echo ""
echo -e "${CPURPLE}-----------------------------${CEND}"
echo -e "${CPURPLE}[  INSTALLATION DE DOVECOT  ]${CEND}"
echo -e "${CPURPLE}-----------------------------${CEND}"
echo ""

echo -e "${CGREEN}-> Installation de dovecot-core, dovecot-imapd, dovecot-lmtpd et dovecot-mysql ${CEND}"
apt-get install -y dovecot-core dovecot-imapd dovecot-lmtpd dovecot-mysql

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

echo -e "${CGREEN}-> Mise en place du fichier /etc/dovecot/dovecot.conf ${CEND}"
cat > /etc/dovecot/dovecot.conf <<EOF
## Dovecot configuration file

# Enable installed protocols
!include_try /usr/share/dovecot/protocols.d/*.protocol
protocols = imap lmtp

# Most of the actual configuration gets included below. The filenames are
# first sorted by their ASCII value and parsed in that order. The 00-prefixes
# in filenames are intended to make it easier to understand the ordering.
!include conf.d/*.conf

# A config file can also tried to be included without giving an error if
# it's not found:
!include_try local.conf
EOF

apt-get -y purge postfix postfix-mysql
apt-get -y autoremove
rm -rf /etc/nginx/sites-enabled/postfixadmin
rm -rf /var/www/postfixadmin/

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

# ##########################################################################

echo ""
echo -e "${CCYAN}----------------------------------${CEND}"
echo -e "${CCYAN}Reprise du script dans 10 secondes${CEND}"
echo -e "${CCYAN}----------------------------------${CEND}"
echo ""
echo -ne '[                  ] 10s \r'
sleep 1
echo -ne '[+                 ] 9s \r'
sleep 1
echo -ne '[+ +               ] 8s \r'
sleep 1
echo -ne '[+ + +             ] 7s \r'
sleep 1
echo -ne '[+ + + +           ] 6s \r'
sleep 1
echo -ne '[+ + + + +         ] 5s \r'
sleep 1
echo -ne '[+ + + + + +       ] 4s \r'
sleep 1
echo -ne '[+ + + + + + +     ] 3s \r'
sleep 1
echo -ne '[+ + + + + + + +   ] 2s \r'
sleep 1
echo -ne '[+ + + + + + + + + ] 1s \r'
sleep 1
echo -ne '[+ + + + + + + + + +] Reprise... \r'
echo -ne '\n'

echo ""
echo -e "${CPURPLE}------------------------------${CEND}"
echo -e "${CPURPLE}[  REDÉMARRAGE DES SERVICES  ]${CEND}"
echo -e "${CPURPLE}------------------------------${CEND}"
echo ""

service nginx restart

if [ $? -ne 0 ]; then
    echo ""
    echo -e "\n ${CRED}/!\ ECHEC: un problème est survenue lors du redémarrage de nginx.${CEND}" 1>&2
    echo -e "\n ${CRED}/!\ Consultez le fichier de log /var/log/nginx/errors.log.${CEND}" 1>&2
    echo ""
fi

service postfix restart

if [ $? -ne 0 ]; then
    echo ""
    echo -e "\n ${CRED}/!\ ECHEC: un problème est survenue lors du redémarrage de postfix.${CEND}" 1>&2
    echo -e "\n ${CRED}/!\ Consultez le fichier de log /var/log/mail.log${CEND}" 1>&2
    echo ""
fi

service dovecot restart

if [ $? -ne 0 ]; then
    echo ""
    echo -e "\n ${CRED}/!\ ECHEC: un problème est survenue lors du redémarrage de dovecot.${CEND}" 1>&2
    echo -e "\n ${CRED}/!\ Consultez le fichier de log /var/log/nginx/errors.log.${CEND}" 1>&2
    echo ""
fi

echo ""
echo -e "${CPURPLE}----------------------------${CEND}"
echo -e "${CPURPLE}[  VERIFICATION DES PORTS  ]${CEND}"
echo -e "${CPURPLE}----------------------------${CEND}"
echo ""

NBPORT=$(netstat -ptna | grep '0.0.0.0:25\|0.0.0.0:587\|0.0.0.0:993' | wc -l)

# Vérification des ports
if [ $NBPORT -ne 3 ]; then
    echo ""
    echo -e "${CRED}/!\ ERREUR: Nombre de port invalide !${CEND}" 1>&2
    echo -e "${CRED}POSTFIX: `service postfix status` !${CEND}" 1>&2
    echo -e "${CRED}DOVECOT: `service dovecot status` !${CEND}" 1>&2
    echo ""
    exit 1
else
    echo -e "${CGREEN}PORTS 25, 587, 993 [OK] ${CEND}"
fi

echo ""
echo -e "${CPURPLE}-------------------${CEND}"
echo -e "${CPURPLE}[  FIN DU SCRIPT  ]${CEND}"
echo -e "${CPURPLE}-------------------${CEND}"
echo ""

# {
#    sleep 0.5
#    echo "helo localhost"
#    sleep 0.5
# } | telnet localhost 25 | grep "250-STARTTLS"

# fgrep -q "250-STARTTLS" /tmp/telnet-smtp-output.tmp
# GREPSTATUS=$?

# if [ $GREPSTATUS -ne 0 ]; then
#     echo ""
#     echo -e "${CRED}/!\ ERREUR: protocole STARTTLS non activé !${CEND}" 1>&2
#     echo ""
#     exit 1
# fi
