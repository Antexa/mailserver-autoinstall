Serveur de mail - Installation automatique
==========================================

Ce script permet d'installer de manière automatique un serveur mail complet avec Postfix, Dovecot et Rainloop.
Topic associé : http://mondedie.fr/viewtopic.php?pid=11746

### Pré-requis :

- ``Debian 7 “wheezy”``
- ``Nginx``
- ``PHP``
- ``MySQL``
- ``OpenSSL``

### Installation

```bash
apt-get update && apt-get dist-upgrade
apt-get install git-core
```

```bash
cd /tmp
git clone https://github.com/hardware/mailserver-autoinstall.git
cd mailserver-autoinstall
chmod +x install.sh && ./install.sh
```

### Désinstallation

Le script de désinstallation permet de supprimer absolument **TOUT** ce qu'à fait le script d'installation. Si vous avez une erreur pendant la configuration du serveur de mail, vous pouvez répartir à zéro avec ce script :

```bash
chmod +x uninstall.sh && ./uninstall.sh
```

Ce script est tiré du tutoriel "Installation sécurisée d'un serveur de mail avec Postfix, Dovecot et Rainloop" : http://mondedie.fr/viewtopic.php?id=5750

### Schéma

![schema](https://meshup.net/img/mail-server-tutorial/schema.png "schema")

Inspiré du script d'installation de rutorrent de ``Ex_Rat`` : https://bitbucket.org/exrat/install-rutorrent

### Support

Si vous avez une question, une remarque ou une suggestion, n'hésitez pas à poster un commentaire sur ce topic : http://mondedie.fr/viewtopic.php?id=5794

### License
MIT. Voir le fichier ``LICENCE`` pour plus de détails
