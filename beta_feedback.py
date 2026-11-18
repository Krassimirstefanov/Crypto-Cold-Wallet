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
import re
import smtplib
import ssl
from email.message import EmailMessage


_HEX_PRIVKEY_RE = re.compile(r"\b(?:0x)?[0-9a-fA-F]{64}\b")
_WIF_PRIVKEY_RE = re.compile(r"\b[5KL][1-9A-HJ-NP-Za-km-z]{50,51}\b")
_HYPHEN_25_RE = re.compile(r"\b(?:[a-zA-Z]{3,12}-){24}[a-zA-Z]{3,12}\b")


def contains_potential_secret(text: str) -> bool:
    """Détecte la présence accidentelle de clés privées, WIF, seeds 12/24/25 mots
    ou en-têtes de coffre dans un message Beta ou rapport de debug."""
    if not isinstance(text, str) or not text.strip():
        return False
    if "KCW2" in text or "private_spend_key" in text or "private_view_key" in text:
        return True
    if _HEX_PRIVKEY_RE.search(text) or _WIF_PRIVKEY_RE.search(text) or _HYPHEN_25_RE.search(text):
        return True
    # Détection d'une séquence de >= 12 mots alphabétiques consécutifs (seed BIP39 / Monero 25 mots)
    words = [w for w in re.split(r"\s+", text.strip()) if w.isalpha() and w.islower() and 3 <= len(w) <= 10]
    if len(words) >= 24:
        return True
    return False


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
    del password
    return missing


def send_beta_message(name: str, reply_to: str, message: str) -> None:
    if contains_potential_secret(message) or contains_potential_secret(name):
        raise ValueError(
            "Envoi bloqué par sécurité : le message semble contenir une clé privée, "
            "un WIF ou une phrase mnémonique/passphrase."
        )
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

    try:
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
    finally:
        pw_buf = bytearray(password.encode("utf-8"))
        for i in range(len(pw_buf)):
            pw_buf[i] = 0
        del password
