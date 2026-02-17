# 📧 Messagerie Sécurisée à Base d’Identité (IBE)
## 🧩 Description du projet

Ce projet consiste en le développement d’une application de messagerie sécurisée en Java intégrant un mécanisme de chiffrement à base d’identité (Identity-Based Encryption – IBE).

L’objectif principal est de permettre l’envoi et la réception d’e-mails contenant des pièces jointes chiffrées, en utilisant l’adresse e-mail du destinataire comme clé publique implicite.

Le système repose sur :

L’API JavaMail pour la gestion des communications SMTP/IMAP

La bibliothèque JPBC pour l’implémentation du schéma IBE basé sur les pairings bilinéaires

Une autorité de confiance (PKG – Private Key Generator) responsable de la génération des paramètres cryptographiques et des clés privées

Une interface graphique permettant l’envoi, la réception et le déchiffrement des pièces jointes

## 🔐 Principe cryptographique

Le projet implémente un schéma de chiffrement à base d’identité inspiré du modèle proposé par Dan Boneh et Matthew Franklin (2001).

Dans ce modèle :

L’adresse e-mail constitue l’identité publique

Une autorité centrale génère une clé maître

Chaque utilisateur obtient sa clé privée auprès de l’autorité

Les pièces jointes sont chiffrées à l’aide des paramètres publics du système

Ce mécanisme repose sur des courbes elliptiques et des pairings bilinéaires via la bibliothèque JPBC.

## 🏗 Architecture du système

Le système est composé de deux entités principales :

1️⃣ Autorité de confiance (PKG)

Génération des paramètres publics

Génération des clés privées à partir des identités (adresses e-mail)

2️⃣ Clients mail sécurisés

Demande de clé privée auprès de l’autorité

Chiffrement des pièces jointes avant envoi

Réception et déchiffrement des pièces jointes

Gestion des e-mails via SMTP/IMAP

## 🛠 Technologies utilisées

Java

JPBC (Java Pairing Based Cryptography)

JavaMail API

Swing / JavaFX (interface graphique)

##🎯 Fonctionnalités principales

Connexion à un compte e-mail via SMTP/IMAP

Envoi d’e-mails avec pièce jointe chiffrée

Réception et téléchargement des pièces jointes

Déchiffrement local des fichiers

Gestion des clés privées associées aux identités

## ⚠️ Limites actuelles

Présence d’un key escrow inhérent au modèle IBE (l’autorité peut générer toutes les clés privées)

Sécurité dépendante de la protection de la clé maître

Implémentation pédagogique non destinée à un usage en production
