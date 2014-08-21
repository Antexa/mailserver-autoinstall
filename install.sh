#!/bin/bash

CSI="\033["
CEND="${CSI}0m"
CRED="${CSI}1;31m"
CGREEN="${CSI}1;32m"
CYELLOW="${CSI}1;33m"
CBLUE="${CSI}1;34m"
CPURPLE="${CSI}1;35m"
CCYAN="${CSI}0;36m"

POSTFIXADMIN_VER="2.91"

# ##########################################################################
# ##########################################################################

clear

if [[ $EUID -ne 0 ]]; then
    echo ""
    echo -e "${CRED}/!\ ERREUR: Ce script doit être exécuté en tant que root.${CEND}" 1>&2
    echo ""
    exit 1
fi

# ##########################################################################
# ##########################################################################

checkBin() {
    echo -e "${CRED}/!\ ERREUR: Le programme '$1' est requis pour cette installation."
}

# Vérification des exécutables
command -v dpkg    > /dev/null 2>&1 || { echo `checkBin dpkg`    >&2; exit 1; }
command -v apt-get > /dev/null 2>&1 || { echo `checkBin apt-get` >&2; exit 1; }

# ##########################################################################
# ##########################################################################

dpkg -s postfix | grep "install ok installed" &> /dev/null

# On vérifie que Postfix n'est pas installé
if [ $? -eq 0 ]; then
    echo ""
    echo -e "${CRED}/!\ ERREUR: Postfix est déjà installé sur le serveur.${CEND}" 1>&2
    echo ""
    exit 1
fi

dpkg -s dovecot-core | grep "install ok installed" > /dev/null 2>&1

# On vérifie que Dovecot n'est pas installé
if [ $? -eq 0 ]; then
    echo ""
    echo -e "${CRED}/!\ ERREUR: Dovecot est déjà installé sur le serveur.${CEND}" 1>&2
    echo ""
    exit 1
fi

dpkg -s opendkim | grep "install ok installed" > /dev/null 2>&1

# On vérifie que OpenDKIM n'est pas installé
if [ $? -eq 0 ]; then
    echo ""
    echo -e "${CRED}/!\ ERREUR: OpenDKIM est déjà installé sur le serveur.${CEND}" 1>&2
    echo ""
    exit 1
fi

# ##########################################################################
# ##########################################################################

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

DOMAIN=$(hostname -d)   # domain.tld
HOSTNAME=$(hostname -s) # hostname
FQDN=$(hostname -f)     # hostname.domain.tld
IPADDR=$(hostname -i)   # Adresse ip

echo "Configuration du FQDN (Fully qualified domain name) du serveur"
echo "-----------------------------------------------------------------------"
echo "[ Votre serveur est actuellement configuré avec les valeurs suivantes ]"
echo -e "DOMAINE    : ${CGREEN}${DOMAIN}${CEND}"
echo -e "NOM D'HOTE : ${CGREEN}${HOSTNAME}${CEND}"
echo -e "FQDN       : ${CGREEN}${FQDN}${CEND}"
echo "-----------------------------------------------------------------------"
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
cat <<'EOF' > /etc/hosts
127.0.0.1 localhost.localdomain localhost
${IPADDR} ${FQDN}               ${HOSTNAME}
EOF

echo ""
echo "-----------------------------------------------------------------------"
echo " [ Après un redémarrage du serveur, les valeurs seront les suivantes ] "
echo -e "DOMAINE    : ${CGREEN}${DOMAIN}${CEND}"
echo -e "NOM D'HOTE : ${CGREEN}${HOSTNAME}${CEND}"
echo -e "FQDN       : ${CGREEN}${FQDN}${CEND}"
echo "-----------------------------------------------------------------------"
echo ""

fi

# ##########################################################################
# ##########################################################################

echo ""
echo -e "${CPURPLE}-----------------------------${CEND}"
echo -e "${CPURPLE}[  INSTALLATION DE POSTFIX  ]${CEND}"
echo -e "${CPURPLE}-----------------------------${CEND}"
echo ""

# Installation de postfix et postfix-mysql
apt-get install -y postfix postfix-mysql

echo -e "${CCYAN}------------------------------------------------------------${CEND}"
read -sp "> Veuillez saisir le mot de passe de l'utilisateur root de MySQL : " MYSQLPASSWD
echo -e "${CCYAN}------------------------------------------------------------${CEND}"

# Création de la base de donnée Postfix
mysqladmin -p $MYSQLPASSWD create postfix

# Génération du mot de passe de l'utilisateur Postfix
PFPASSWD=$(strings /dev/urandom | grep -o '[1-9A-NP-Za-np-z]' | head -n 10 | tr -d '\n')
SQLQUERY="GRANT ALL PRIVILEGES ON postfix.* TO 'postfix'@'127.0.0.1' IDENTIFIED BY '${PFPASSWD}';FLUSH PRIVILEGES;"

# Création de l'utilisateur Postfix
mysql -h "localhost" -u "root" -p $MYSQLPASSWD "postfix" -e $SQLQUERY

# ##########################################################################
# ##########################################################################

echo ""
echo -e "${CPURPLE}----------------------------------${CEND}"
echo -e "${CPURPLE}[  INSTALLATION DE POSTFIXADMIN  ]${CEND}"
echo -e "${CPURPLE}----------------------------------${CEND}"
echo ""

# Téléchargement de PostfixAdmin
cd /var/www && wget "http://downloads.sourceforge.net/project/postfixadmin/postfixadmin/postfixadmin-${POSTFIXADMIN_VER}/postfixadmin-${POSTFIXADMIN_VER}.tar.gz"
tar -xzf postfixadmin-$POSTFIXADMIN_VER.tar.gz
mv postfixadmin-$POSTFIXADMIN_VER postfixadmin
rm -rf postfixadmin-$POSTFIXADMIN_VER.tar.gz
chown -R www-data:www-data postfixadmin

PFACONFIG="/var/www/postfixadmin/config.inc.php"

# Modification du fichier de configuration de PostfixAdmin
sed -i -e "s/\($CONF['configured'] =\).*/\1 true/"                 $PFACONFIG
sed -i -e "s/\($CONF['default_language'] =\).*/\1 'fr'/"           $PFACONFIG
sed -i -e "s/\($CONF['database_type'] =\).*/\1 'mysqli'/"          $PFACONFIG
sed -i -e "s/\($CONF['database_host'] =\).*/\1 'localhost'/"       $PFACONFIG
sed -i -e "s/\($CONF['database_user'] =\).*/\1 'postfix'/"         $PFACONFIG
sed -i -e "s/\($CONF['database_password'] =\).*/\1 '${PFPASSWD}'/" $PFACONFIG
sed -i -e "s/\($CONF['database_name'] =\).*/\1 'postfix'/"         $PFACONFIG
sed -i -e "s/\($CONF['admin_email'] =\).*/\1 'admin@${DOMAIN}'/"   $PFACONFIG
sed -i -e "s/\($CONF['domain_path'] =\).*/\1 'YES'/"               $PFACONFIG
sed -i -e "s/\($CONF['domain_in_mailbox'] =\).*/\1 'NO'/"          $PFACONFIG
sed -i -e "s/\($CONF['fetchmail'] =\).*/\1 'NO'/"                  $PFACONFIG

echo -e "${CCYAN}--------------------------------------------------------${CEND}"
read -p "Veuillez saisir le chemin absolu du fichier PASSWD de nginx : " PASSWDPATH
echo -e "${CCYAN}--------------------------------------------------------${CEND}"

# Ajout du vhost postfixadmin
cat <<'EOF' > /etc/nginx/sites-enabled/postfixadmin
server {
   listen 80;
   server_name     postfixadmin.${DOMAIN};
   root            /var/www/postfixadmin;
   index           index.php;
   charset         utf-8;

   auth_basic "PostfixAdmin - Connexion";
   auth_basic_user_file ${PASSWDPATH};

   location / {
      try_files $uri $uri/ index.php;
   }

   location ~* \.php$ {
        include       /etc/nginx/fastcgi_params;
        fastcgi_pass  unix:/var/run/php5-fpm.sock;
        fastcgi_index index.php;
   }
}
EOF

# Redémarrage de nginx pour prendre en compte le nouveau vhost
service nginx restart

echo ""
echo -e "${CCYAN}------------------------------------------------------------${CEND}"
echo -e "${CYELLOW} Pour finaliser l'installation de PostfixAdmin, aller à l'adresse suivante : ${CEND}"
echo -e "${CCYAN}> http://postfixadmin.${DOMAIN}/setup.php${CEND}"
echo -e "${CYELLOW}Veuillez vous assurer que tous les pré-requis ont été validés.${CEND}"
echo -e "${CYELLOW}Une votre compte administrateur créé, saisissez le hash généré.${CEND}"
echo ""
read -p "> Veuillez saisir le hash généré par le setup : " PFAHASH
echo ""
echo -e "${CCYAN}------------------------------------------------------------${CEND}"

# Ajout du hash du setup dans le fichier config.inc.php
sed -i -e "s/\($CONF['setup_password'] =\).*/\1 ${PFAHASH}/" $PFACONFIG

echo -e "Vous pouvez dès à présent vous connecter à PostfixAdmin avec votre compte administrateur."
echo -e "> http://postfixadmin.${DOMAIN}/login.php"
echo -e "Veuillez ajouter au minimum les éléments ci-dessous : "
echo -e "- Votre domaine : ${domain}"
echo -e "- Une adresse email : admin@${domain} (par exemple)"

echo ""
echo "------------------------------------"
echo " Reprise du script dans 20 secondes "
echo "------------------------------------"
echo ""
echo -ne '[                    ] 20s \r'
sleep 1
echo -ne '[+                   ] 19s \r'
sleep 1
echo -ne '[++                  ] 18s \r'
sleep 1
echo -ne '[+++                 ] 17s \r'
sleep 1
echo -ne '[++++                ] 16s \r'
sleep 1
echo -ne '[+++++               ] 15s \r'
sleep 1
echo -ne '[++++++              ] 14s \r'
sleep 1
echo -ne '[+++++++             ] 13s \r'
sleep 1
echo -ne '[++++++++            ] 12s \r'
sleep 1
echo -ne '[+++++++++           ] 11s \r'
sleep 1
echo -ne '[++++++++++          ] 10s \r'
sleep 1
echo -ne '[+++++++++++         ] 9s \r'
sleep 1
echo -ne '[++++++++++++        ] 8s \r'
sleep 1
echo -ne '[+++++++++++++       ] 7s \r'
sleep 1
echo -ne '[++++++++++++++      ] 6s \r'
sleep 1
echo -ne '[+++++++++++++++     ] 5s \r'
sleep 1
echo -ne '[++++++++++++++++    ] 4s \r'
sleep 1
echo -ne '[+++++++++++++++++   ] 3s \r'
sleep 1
echo -ne '[++++++++++++++++++  ] 2s \r'
sleep 1
echo -ne '[+++++++++++++++++++ ] 1s \r'
sleep 1
echo -ne '[++++++++++++++++++++] Reprise... \r'
echo -ne '\n'

# ##########################################################################
# ##########################################################################

echo ""
echo -e "${CPURPLE}------------------------------${CEND}"
echo -e "${CPURPLE}[  CONFIGURATION DE POSTFIX  ]${CEND}"
echo -e "${CPURPLE}------------------------------${CEND}"
echo ""

echo -e "${CGREEN}-> Mise en place du fichier de configuration principal ${CEND}"
cat <<'EOF' > /etc/postfix/main.cf
smtpd_banner = $myhostname ESMTP $mail_name (Debian/GNU)
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
smtpd_sasl_tls_security_options = $smtpd_sasl_security_options
smtpd_sasl_local_domain = $mydomain
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
mailbox_command = procmail -a "$EXTENSION"
mailbox_size_limit = 0
recipient_delimiter = +
inet_interfaces = all
inet_protocols = ipv4, ipv6
smtp_address_preference = any
EOF

SSLOPTS="req -new -x509 -days 1095 -nodes -newkey rsa:4096"

echo -e "${CGREEN}-> Création du certificat SSL ${CEND}"
openssl $SSLOPTS -out /etc/ssl/certs/server.crt -keyout /etc/ssl/private/server.key <<EOF
FR
France
Paris
UNKNOWN
UNKNOWN
${FQDN}
admin@${DOMAIN}
EOF

echo -e "${CGREEN}-> Création du fichier mysql-virtual-mailbox-domains.cf ${CEND}"

cat <<'EOF' > /etc/postfix/mysql-virtual-mailbox-domains.cf
hosts = 127.0.0.1
user = postfix
password = ${PFPASSWD}
dbname = postfix

query = SELECT domain FROM domain WHERE domain='%s' and backupmx = 0 and active = 1
EOF

echo -e "${CGREEN}-> Création du fichier mysql-virtual-mailbox-maps.cf ${CEND}"

cat <<'EOF' > /etc/postfix/mysql-virtual-mailbox-maps.cf
hosts = 127.0.0.1
user = postfix
password = ${PFPASSWD}
dbname = postfix

query = SELECT maildir FROM mailbox WHERE username='%s' AND active = 1
EOF

echo -e "${CGREEN}-> Création du fichier mysql-virtual-alias-maps.cf ${CEND}"

cat <<'EOF' > /etc/postfix/mysql-virtual-alias-maps.cf
hosts = 127.0.0.1
user = postfix
password = ${PFPASSWD}
dbname = postfix

query = SELECT goto FROM alias WHERE address='%s' AND active = 1
EOF

###################################################
# décommenter les lignes dans le fichier /etc/postfix/master.cf
###################################################

echo ""
echo -e "${CPURPLE}-----------------------------${CEND}"
echo -e "${CPURPLE}[  INSTALLATION DE DOVECOT  ]${CEND}"
echo -e "${CPURPLE}-----------------------------${CEND}"
echo ""

apt-get install -y dovecot-core dovecot-imapd dovecot-lmtpd dovecot-mysql

# Création du conteneur MAILDIR
mkdir -p /var/mail/vhosts/${DOMAIN}

# Création d'un nouvel utilisateur nommé vmail avec un UID/GID de 5000
groupadd -g 5000 vmail
useradd -g vmail -u 5000 vmail -d /var/mail
chown -R vmail:vmail /var/mail

# Positionnement des droits sur le répertoire /etc/dovecot
chown -R vmail:dovecot /etc/dovecot
chmod -R o-rwx /etc/dovecot

# Déplacement du certificat SSL et de la clé privée dans les répertoires par défaut
mv /etc/dovecot/dovecot.pem /etc/ssl/certs
mv /etc/dovecot/private/dovecot.pem /etc/ssl/private

# Création des fichiers de configuration
echo -e "${CGREEN}-> Mise en place du fichier /etc/dovecot/dovecot.conf ${CEND}"

cat <<'EOF' > /etc/dovecot/dovecot.conf
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

echo -e "${CGREEN}-> Mise en place du fichier /etc/dovecot/conf.d/10-mail.conf ${CEND}"

cat <<'EOF' > /etc/dovecot/conf.d/10-mail.conf
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

cat <<'EOF' > /etc/dovecot/conf.d/10-auth.conf
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

cat <<'EOF' > /etc/dovecot/conf.d/auth-sql.conf.ext
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

cat <<'EOF' > /etc/dovecot/dovecot-sql.conf.ext
# Paramètres de connexion
driver = mysql
connect = host=127.0.0.1 dbname=postfix user=postfix password=${PFPASSWD}

# Permet de définir l'algorithme de hachage.
# Pour plus d'information: http://wiki2.dovecot.org/Authentication/PasswordSchemes
# /!\ ATTENTION : ne pas oublier de modifier le paramètre $CONF['encrypt'] de PostfixAdmin
default_pass_scheme = MD5-CRYPT

# Requête de récupération du mot de passe du compte utilisateur
password_query = SELECT password FROM mailbox WHERE username = '%u'
EOF

echo -e "${CGREEN}-> Mise en place du fichier /etc/dovecot/conf.d/10-master.conf ${CEND}"

cat <<'EOF' > /etc/dovecot/conf.d/10-master.conf
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

cat <<'EOF' > /etc/dovecot/conf.d/10-ssl.conf
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
# ##########################################################################

echo ""
echo "------------------------------------"
echo " Reprise du script dans 10 secondes "
echo "------------------------------------"
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

# Redémarrage des services
service nginx   restart
service postfix restart
service dovecot restart

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
echo -e "${CPURPLE}---------------------------------------${CEND}"
echo -e "${CPURPLE}[  PUUUUUUUUURRRRRRRRRRGGGGGGGEEEEEE  ]${CEND}"
echo -e "${CPURPLE}---------------------------------------${CEND}"
echo ""

apt-get -y purge postfix postfix-mysql dovecot-core dovecot-imapd dovecot-lmtpd dovecot-mysql opendkim opendkim-tools
apt-get -y autoremove
apt-get -y autoremove
apt-get -y autoremove
apt-get -y autoremove
apt-get -y clean

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
