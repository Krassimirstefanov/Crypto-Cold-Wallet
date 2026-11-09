# -*- coding: utf-8 -*-
"""Envoi volontaire de retours Beta par e-mail.

Aucune donnée du wallet n'est envoyée automatiquement. Seuls les champs saisis
par l'utilisateur dans la rubrique Beta sont transmis, après confirmation.

Configuration (variables d'environnement):
  WALLET_BETA_EMAIL        adresse destinataire
  WALLET_BETA_SMTP_HOST    serveur SMTP
  WALLET_BETA_SMTP_PORT    port (587 par défaut)
  WALLET_BETA_SMTP_USER    utilisateur SMTP
  WALLET_BETA_SMTP_PASSWORD mot de passe / mot de passe d'application
  WALLET_BETA_SMTP_FROM    expéditeur (par défaut SMTP_USER)
  WALLET_BETA_SMTP_SECURITY starttls (défaut) ou ssl

Ne jamais intégrer les identifiants SMTP dans une version distribuée publiquement.
Pour une distribution publique, utiliser plutôt un petit endpoint HTTPS côté
serveur, afin que le secret SMTP reste sur le serveur.
"""
from __future__ import annotations

import os
import smtplib
import ssl
from email.message import EmailMessage


def _cfg(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()


def configuration_status():
    recipient = _cfg("WALLET_BETA_EMAIL")
    host = _cfg("WALLET_BETA_SMTP_HOST")
    user = _cfg("WALLET_BETA_SMTP_USER")
    password = _cfg("WALLET_BETA_SMTP_PASSWORD")
    missing = []
    if not recipient: missing.append("WALLET_BETA_EMAIL")
    if not host: missing.append("WALLET_BETA_SMTP_HOST")
    if not user: missing.append("WALLET_BETA_SMTP_USER")
    if not password: missing.append("WALLET_BETA_SMTP_PASSWORD")
    return missing


def send_beta_message(name: str, reply_to: str, message: str) -> None:
    missing = configuration_status()
    if missing:
        raise RuntimeError("Configuration Beta incomplète : " + ", ".join(missing))

    recipient = _cfg("WALLET_BETA_EMAIL")
    host = _cfg("WALLET_BETA_SMTP_HOST")
    port = int(_cfg("WALLET_BETA_SMTP_PORT", "587"))
    user = _cfg("WALLET_BETA_SMTP_USER")
    password = _cfg("WALLET_BETA_SMTP_PASSWORD")
    sender = _cfg("WALLET_BETA_SMTP_FROM", user)
    security = _cfg("WALLET_BETA_SMTP_SECURITY", "starttls").lower()

    mail = EmailMessage()
    mail["Subject"] = "Crypto Cold Wallet — message Beta"
    mail["From"] = sender
    mail["To"] = recipient
    if reply_to:
        mail["Reply-To"] = reply_to
    mail.set_content(
        "Message envoyé volontairement depuis la rubrique Beta.\n\n"
        f"Nom / pseudo : {name or '(non renseigné)'}\n"
        f"E-mail de réponse : {reply_to or '(non renseigné)'}\n\n"
        "Message :\n"
        f"{message}\n"
    )

    context = ssl.create_default_context()
    if security == "ssl":
        with smtplib.SMTP_SSL(host, port, context=context, timeout=20) as smtp:
            smtp.login(user, password)
            smtp.send_message(mail)
    elif security == "starttls":
        with smtplib.SMTP(host, port, timeout=20) as smtp:
            smtp.ehlo()
            smtp.starttls(context=context)
            smtp.ehlo()
            smtp.login(user, password)
            smtp.send_message(mail)
    else:
        raise RuntimeError("WALLET_BETA_SMTP_SECURITY doit valoir 'starttls' ou 'ssl'.")
