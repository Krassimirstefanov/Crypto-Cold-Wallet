"""Contrôles d'accès Easy / Medium / Advanced.

Le niveau d'accès complète Argon2id/AES-GCM ; il ne le remplace jamais.
"""

import base64
import hashlib
import hmac
import json
import secrets
import string
from getpass import getpass
from pathlib import Path

import security_core as sec
from i18n import get_lang


BASE = Path(__file__).resolve().parent
SECONDARY_FILE = BASE / "security_access.enc"
WARNING = (
    "! Do not share this credential with anyone. Write it down and keep it "
    "offline (USB key or physical paper note).\n"
    "! If you lose any of your passwords, you will not be able to recover "
    "your money!"
)


def _secret(prompt):
    try:
        return getpass(prompt)
    except (EOFError, OSError):
        return input(prompt)


def get_access_level(default="easy"):
    try:
        data = json.loads(sec.CONFIG_FILE.read_text(encoding="utf-8"))
        level = data.get("access_level")
        if level in {"easy", "medium", "advanced"}:
            return level
    except (OSError, ValueError, TypeError):
        pass
    return default


def set_access_level(level):
    if level not in {"easy", "medium", "advanced"}:
        raise ValueError("Unknown access level")
    try:
        data = json.loads(sec.CONFIG_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        data = {}
    data["access_level"] = level
    sec.atomic_write(sec.CONFIG_FILE, (json.dumps(data, indent=2) + "\n").encode())


def choose_access_level():
    green, yellow, red, reset = "\033[92m", "\033[93m", "\033[91m", "\033[0m"
    lang = get_lang()
    if lang == "fr":
        print("\nChoisissez votre niveau de sécurité")
        print(f"  {green}1) Facile — Pratique{reset} : seule la masterkey est demandée à chaque ouverture.")
        print(f"  {yellow}2) Moyen — Recommandé{reset} : un mot de passe secondaire protège les transferts, l'historique et les bénéficiaires.")
        print(f"  {red}3) Avancé — Compartimentation maximale{reset} : chaque wallet reçoit aussi sa propre passphrase de 25 mots.")
        print("\n  Explication du mode Avancé :")
        print("  - Cinq mots choisis aléatoirement autorisent la consultation du solde public.")
        print("  - Les 25 mots sont nécessaires pour déchiffrer les secrets, révéler les clés ou signer un transfert.")
        print("  - Une passphrase de wallet perdue ne peut pas être récupérée.")
    elif lang == "es":
        print("\nElija su nivel de seguridad")
        print(f"  {green}1) Fácil — Práctico{reset}: solo se requiere la clave maestra al abrir.")
        print(f"  {yellow}2) Medio — Recomendado{reset}: una contraseña secundaria protege transferencias, historial y beneficiarios.")
        print(f"  {red}3) Avanzado — Compartimentación máxima{reset}: cada wallet recibe una frase de 25 palabras.")
        print("\n  Avanzado: 5 palabras aleatorias para consultar saldos; las 25 para revelar claves o firmar. Una frase perdida no puede recuperarse.")
    elif lang == "de":
        print("\nWählen Sie Ihre Sicherheitsstufe")
        print(f"  {green}1) Einfach — Bequem{reset}: Beim Öffnen wird nur der Masterkey benötigt.")
        print(f"  {yellow}2) Mittel — Empfohlen{reset}: Ein zweites Passwort schützt Überweisungen, Verlauf und Begünstigte.")
        print(f"  {red}3) Erweitert — Maximale Trennung{reset}: Jede Wallet erhält eine eigene 25-Wörter-Passphrase.")
        print("\n  Erweitert: 5 zufällige Wörter für Salden; alle 25 zum Anzeigen von Schlüsseln oder Signieren. Verlorene Passphrasen sind nicht wiederherstellbar.")
    elif lang == "it":
        print("\nScegli il livello di sicurezza")
        print(f"  {green}1) Facile — Comodo{reset}: all'apertura serve solo la masterkey.")
        print(f"  {yellow}2) Medio — Consigliato{reset}: una password secondaria protegge trasferimenti, cronologia e beneficiari.")
        print(f"  {red}3) Avanzato — Compartimentazione massima{reset}: ogni wallet riceve una passphrase di 25 parole.")
        print("\n  Avanzato: 5 parole casuali per i saldi; tutte le 25 per mostrare chiavi o firmare. Una passphrase persa non è recuperabile.")
    elif lang == "pt":
        print("\nEscolha o nível de segurança")
        print(f"  {green}1) Fácil — Prático{reset}: apenas a chave mestra é pedida ao abrir.")
        print(f"  {yellow}2) Médio — Recomendado{reset}: uma senha secundária protege transferências, histórico e beneficiários.")
        print(f"  {red}3) Avançado — Compartimentação máxima{reset}: cada wallet recebe uma frase de 25 palavras.")
        print("\n  Avançado: 5 palavras aleatórias para saldos; todas as 25 para revelar chaves ou assinar. Uma frase perdida não pode ser recuperada.")
    elif lang == "ru":
        print("\nВыберите уровень безопасности")
        print(f"  {green}1) Простой{reset}: при открытии нужен только мастер-ключ.")
        print(f"  {yellow}2) Средний{reset}: второй пароль защищает переводы, историю и получателей.")
        print(f"  {red}3) Продвинутый{reset}: каждый кошелёк получает фразу из 25 слов.")
        print("\n  Продвинутый: 5 случайных слов для баланса; все 25 для ключей и подписи. Утерянную фразу восстановить нельзя.")
    elif lang == "zh":
        print("\n选择安全级别")
        print(f"  {green}1) 简单{reset}：打开时只需主密码。")
        print(f"  {yellow}2) 中等 — 推荐{reset}：第二密码保护转账、历史和收款人。")
        print(f"  {red}3) 高级{reset}：每个钱包使用独立的25词密码短语。")
        print("\n  高级：查看余额需随机5词；显示密钥或签名需全部25词。丢失后无法恢复。")
    elif lang == "ja":
        print("\nセキュリティレベルを選択")
        print(f"  {green}1) 簡単{reset}：起動時はマスターキーのみ。")
        print(f"  {yellow}2) 中級 — 推奨{reset}：第2パスワードで送金、履歴、受取人を保護。")
        print(f"  {red}3) 上級{reset}：各ウォレットに25語のパスフレーズ。")
        print("\n  上級：残高確認はランダムな5語、鍵の表示と署名は全25語。紛失時は復元できません。")
    elif lang == "ko":
        print("\n보안 수준을 선택하세요")
        print(f"  {green}1) 쉬움{reset}: 실행 시 마스터키만 필요합니다.")
        print(f"  {yellow}2) 중간 — 권장{reset}: 보조 암호가 송금, 기록, 수취인을 보호합니다.")
        print(f"  {red}3) 고급{reset}: 각 지갑에 25단어 암호문을 사용합니다.")
        print("\n  고급: 잔액은 임의 5단어, 키 표시와 서명은 25단어 전체가 필요합니다. 분실 시 복구할 수 없습니다.")
    elif lang == "nl":
        print("\nKies uw beveiligingsniveau")
        print(f"  {green}1) Eenvoudig{reset}: alleen de masterkey is nodig bij het openen.")
        print(f"  {yellow}2) Gemiddeld — Aanbevolen{reset}: een tweede wachtwoord beschermt overdrachten, geschiedenis en begunstigden.")
        print(f"  {red}3) Geavanceerd{reset}: elke wallet krijgt een wachtzin van 25 woorden.")
        print("\n  Geavanceerd: 5 willekeurige woorden voor saldo; alle 25 voor sleutels of ondertekening. Verlies is niet herstelbaar.")
    elif lang == "pl":
        print("\nWybierz poziom bezpieczeństwa")
        print(f"  {green}1) Łatwy{reset}: przy otwarciu wymagany jest tylko klucz główny.")
        print(f"  {yellow}2) Średni — Zalecany{reset}: drugie hasło chroni przelewy, historię i beneficjentów.")
        print(f"  {red}3) Zaawansowany{reset}: każdy wallet ma frazę 25 słów.")
        print("\n  Zaawansowany: 5 losowych słów do salda; wszystkie 25 do kluczy lub podpisu. Utraconej frazy nie można odzyskać.")
    elif lang == "tr":
        print("\nGüvenlik seviyenizi seçin")
        print(f"  {green}1) Kolay{reset}: açılışta yalnızca ana anahtar gerekir.")
        print(f"  {yellow}2) Orta — Önerilen{reset}: ikinci parola transferleri, geçmişi ve alıcıları korur.")
        print(f"  {red}3) Gelişmiş{reset}: her cüzdan 25 kelimelik parola alır.")
        print("\n  Gelişmiş: bakiye için rastgele 5 kelime; anahtarlar ve imza için 25 kelimenin tamamı gerekir. Kayıp parola kurtarılamaz.")
    elif lang in {"ar", "he"}:
        rtl = {
            "ar": ("اختر مستوى الأمان", "سهل: المفتاح الرئيسي فقط عند الفتح.", "متوسط: كلمة مرور ثانية تحمي التحويلات والسجل والمستفيدين.", "متقدم: عبارة من 25 كلمة لكل محفظة؛ 5 كلمات للرصيد و25 للكشف أو التوقيع. لا يمكن استعادتها عند فقدها."),
            "he": ("בחרו רמת אבטחה", "קל: רק מפתח ראשי בפתיחה.", "בינוני: סיסמה שנייה מגינה על העברות, היסטוריה ומוטבים.", "מתקדם: ביטוי בן 25 מילים לכל ארנק; 5 מילים ליתרה וכל 25 לחשיפה או חתימה. אין אפשרות שחזור."),
        }[lang]
        print("\n" + rtl[0]); print(f"  {green}1) {rtl[1]}{reset}"); print(f"  {yellow}2) {rtl[2]}{reset}"); print(f"  {red}3) {rtl[3]}{reset}")
    else:
        print("\nChoose your security level")
        print(f"  {green}1) Easy — Convenient{reset}: Only the masterkey is required at each opening.")
        print(f"  {yellow}2) Medium — Recommended{reset}: A secondary password protects transfers, history, and beneficiary data.")
        print(f"  {red}3) Advanced — Maximum compartmentalization{reset}: Each wallet also receives its own 25-word passphrase.")
        print("\n  Advanced explanation:")
        print("  - Five randomly selected words authorize public balance consultation.")
        print("  - All 25 words are required to decrypt secrets, reveal keys, or sign a transfer.")
        print("  - A wallet passphrase cannot be recovered if it is lost.")
    while True:
        choice = input("\nSecurity level [1-3]: ").strip()
        level = {"1": "easy", "2": "medium", "3": "advanced"}.get(choice)
        if level:
            print("\n" + WARNING)
            while True:
                confirm = input(f"\nContinue with {level.capitalize()}? (y/n): ").strip().lower()
                if confirm in {"y", "yes"}:
                    return level
                if confirm in {"n", "no"}:
                    print("\nChoose another security level.")
                    break
                print("! Please answer y or n.")
            continue
        print("! Invalid choice.")


def _valid_password(value):
    return (20 <= len(value) <= 80 and any(c.islower() for c in value)
            and any(c.isupper() for c in value) and any(c.isdigit() for c in value)
            and any(not c.isalnum() for c in value))


def generate_password(length=40):
    if not 20 <= length <= 80:
        raise ValueError("Password length must be between 20 and 80")
    groups = [string.ascii_lowercase, string.ascii_uppercase,
              string.digits, "!#$%&()*+,-./:;<=>?@[]^_{|}~"]
    chars = [secrets.choice(group) for group in groups]
    alphabet = "".join(groups)
    chars.extend(secrets.choice(alphabet) for _ in range(length - len(chars)))
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


def ask_password(name):
    print(f"\n! {name}")
    print("  1) Put your own password (20 to 80 characters)")
    print("  2) Generate a secure password automatically")
    while True:
        choice = input("Choice: ").strip()
        if choice == "1":
            value = _secret(f"{name}: ")
            if not _valid_password(value):
                print("! Use 20-80 characters with lowercase, uppercase, digits, and symbols.")
                continue
            if not hmac.compare_digest(value, _secret("Confirm password: ")):
                print("! Passwords do not match.")
                continue
        elif choice == "2":
            value = generate_password()
            print(f"\nGenerated {name}:\n{value}\n")
        else:
            print("! Invalid choice.")
            continue
        print(WARNING)
        input("Press Enter only after saving it offline: ")
        return value


def _password_verifier(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2**15, r=8, p=1,
                            maxmem=64 * 1024 * 1024)
    return base64.b64encode(salt).decode(), base64.b64encode(digest).decode()


def configure_secondary(masterkey):
    password = ask_password("Secondary password")
    salt, digest = _password_verifier(password)
    sec.save_encrypted_json(SECONDARY_FILE, {"salt": salt, "digest": digest}, masterkey)
    del password


def get_verified_secondary(masterkey):
    if get_access_level() == "easy":
        return ""
    try:
        data = sec.load_encrypted_json(SECONDARY_FILE, masterkey)
        password = _secret("! Secondary password: ")
        salt = base64.b64decode(data["salt"])
        _, candidate = _password_verifier(password, salt)
        if hmac.compare_digest(candidate, data["digest"]):
            return password
        del password
    except Exception:
        pass
    print("! Incorrect secondary password. Access denied.")
    return None


def verify_secondary(masterkey):
    credential = get_verified_secondary(masterkey)
    valid = credential is not None
    if credential:
        del credential
    return valid


def generate_wallet_passphrase():
    try:
        from mnemonic import Mnemonic
        words = Mnemonic("english").wordlist
    except Exception:
        words = ("amber anchor apple atlas bamboo beacon birch breeze bridge cactus "
                 "cedar cipher cloud comet coral cosmos crystal delta eagle ember falcon "
                 "forest frost galaxy garden harbor island jade lantern lunar maple meadow "
                 "meteor mountain nebula ocean olive orchid pebble pine prism quartz raven "
                 "river rocket shadow silver solar stone summit thunder tiger valley violet "
                 "willow winter zenith").split()
    return "-".join(secrets.choice(words) for _ in range(25))


def validate_wallet_passphrase(value):
    words = value.strip().lower().split("-")
    return len(words) == 25 and all(word.isalpha() for word in words)


def ask_wallet_passphrase(label):
    print(f"\n! Wallet passphrase for {label}")
    print("  1) Put your own passphrase: exactly 25 words separated by '-'")
    print("  2) Generate a 25-word passphrase automatically")
    while True:
        choice = input("Choice: ").strip()
        if choice == "1":
            phrase = _secret("25-word passphrase: ").strip().lower()
            if not validate_wallet_passphrase(phrase):
                print("! Expected exactly 25 alphabetic words separated by '-'.")
                continue
            if not hmac.compare_digest(phrase, _secret("Confirm passphrase: ").strip().lower()):
                print("! Passphrases do not match.")
                continue
        elif choice == "2":
            phrase = generate_wallet_passphrase()
            print(f"\nGenerated wallet passphrase:\n{phrase}\n")
        else:
            print("! Invalid choice.")
            continue
        print(WARNING)
        input("Press Enter only after saving all 25 words offline: ")
        return phrase


def protect_wallet_secrets(wallet, phrase, protection="advanced"):
    secret_names = {k for k in wallet if any(part in k.lower() for part in
                    ("private", "mnemonic", "seed", "secret"))}
    secrets_payload = {key: wallet.pop(key) for key in secret_names}
    wallet["protected_secrets"] = base64.b64encode(
        sec.encrypt_json(secrets_payload, phrase, mode="maximum")
    ).decode()
    wallet["secret_protection"] = protection
    if protection != "advanced":
        return wallet
    salt = secrets.token_bytes(16)
    words = phrase.split("-")
    wallet["word_challenge"] = {
        "salt": base64.b64encode(salt).decode(),
        "hashes": [hashlib.sha256(salt + i.to_bytes(2, "big") + word.encode()).hexdigest()
                   for i, word in enumerate(words, 1)],
    }
    return wallet


def unlock_wallet_secrets(wallet, phrase):
    blob = base64.b64decode(wallet["protected_secrets"])
    return sec.decrypt_json(blob, phrase)


def ask_wallet_credential(wallet, purpose="this sensitive operation", secondary_password=None):
    if wallet.get("secret_protection") == "secondary":
        print(f"\n! The secondary password is required for {purpose}.")
        credential = secondary_password if secondary_password is not None else _secret("Secondary password: ")
        try:
            unlock_wallet_secrets(wallet, credential)
            return credential
        except Exception:
            print("! Incorrect secondary password. Access denied.")
            return None
    return ask_full_wallet_passphrase(wallet, purpose)


def ask_full_wallet_passphrase(wallet, purpose="this sensitive operation"):
    print(f"\n! All 25 wallet words are required for {purpose}.")
    phrase = _secret("Wallet passphrase: ").strip().lower()
    if not validate_wallet_passphrase(phrase):
        print("! Invalid 25-word passphrase format.")
        return None
    try:
        unlock_wallet_secrets(wallet, phrase)
        return phrase
    except Exception:
        print("! Incorrect wallet passphrase. Access denied.")
        return None


def verify_five_words(wallet):
    challenge = wallet.get("word_challenge") or {}
    hashes = challenge.get("hashes") or []
    if len(hashes) != 25:
        print("! This wallet has no valid Advanced challenge data.")
        return False
    salt = base64.b64decode(challenge["salt"])
    positions = sorted(secrets.SystemRandom().sample(range(1, 26), 5))
    print("! Enter the five requested wallet words. Their positions change each time.")
    for position in positions:
        word = _secret(f"  Word #{position}: ").strip().lower()
        digest = hashlib.sha256(salt + position.to_bytes(2, "big") + word.encode()).hexdigest()
        if not hmac.compare_digest(digest, hashes[position - 1]):
            print("! Incorrect word. Balance access denied.")
            return False
    return True
