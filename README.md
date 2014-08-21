##### /!\ ATTENTION : Ce script est en cours de développement, il n'est pas complètement fonctionnel. Veuillez ne pas l'utiliser sur votre serveur pour le moment.

====================================================================================

Serveur de mail - Installation automatique
==========================================

Ce script permet d'installer de manière automatique un serveur mail complet avec Postfix, Dovecot et Rainloop.

### Pré-requis :

- ``Debian 7 “wheezy”``
- ``Nginx``
- ``PHP``
- ``MySQL``
- ``OpenSSL``

### Installation

```bash
cd /tmp
git clone https://github.com/hardware/mailserver-autoinstall.git
cd mailserver-autoinstall
chmod a+x install.sh && ./install.sh
```

Ce script est tiré du tutoriel "Installation sécurisée d'un serveur de mail avec Postfix, Dovecot et Rainloop" : http://mondedie.fr/viewtopic.php?id=5750

### Schéma

![schema](https://meshup.net/img/mail-server-tutorial/schema.png "schema")

Inspiré du script d'installation de rutorrent de ``Ex_Rat`` : https://bitbucket.org/exrat/install-rutorrent

### Support

Si vous avez une question, une remarque ou une suggestion, n'hésitez pas à poster un commentaire sur ce topic : http://mondedie.fr/viewtopic.php?pid=11270

### License
MIT. Voir le fichier ``LICENCE`` pour plus de détails
