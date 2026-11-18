"""Écran graphique de démarrage du portefeuille.

Ce module n'accède ni au coffre, ni au réseau, ni aux clés. Il présente
uniquement l'identité visuelle avant le déverrouillage du programme.
"""

from pathlib import Path


BASE = Path(__file__).resolve().parent
LOGO = BASE / "assets" / "crypto_wallet_logo.png"
FIRST_LAUNCH_MARKER = BASE / "wallets" / ".onboarding_complete"


def is_first_launch() -> bool:
    return not FIRST_LAUNCH_MARKER.exists()


def mark_first_launch_complete() -> None:
    FIRST_LAUNCH_MARKER.parent.mkdir(parents=True, exist_ok=True)
    FIRST_LAUNCH_MARKER.write_text("completed\n", encoding="utf-8")


def show_startup_splash(duration_ms: int = 2400, first_launch: bool = False) -> bool:
    """Affiche le splash à chaque lancement et renvoie True s'il a été montré.

    Échap, Entrée ou un clic permettent de le fermer immédiatement. Sur une
    machine sans environnement graphique, le démarrage terminal continue.
    """
    try:
        import tkinter as tk

        root = tk.Tk()
        root.withdraw()
        root.title("Crypto Cold Wallet")
        root.configure(bg="#081222")
        root.resizable(False, False)
        root.overrideredirect(True)

        width, height = (900, 900) if first_launch else (720, 540)
        x = max(0, (root.winfo_screenwidth() - width) // 2)
        y = max(0, (root.winfo_screenheight() - height) // 2)
        root.geometry(f"{width}x{height}+{x}+{y}")

        panel = tk.Frame(root, bg="#081222", highlightbackground="#27375c",
                         highlightthickness=1)
        panel.pack(fill="both", expand=True)

        logo = tk.PhotoImage(file=str(LOGO))
        # Le fichier fait environ 1254 px : /4 donne un emblème compact.
        logo = logo.subsample(5 if first_launch else 4,
                              5 if first_launch else 4)
        logo_label = tk.Label(panel, image=logo, bg="#081222", borderwidth=0)
        logo_label.image = logo
        logo_label.pack(pady=(38, 8))

        tk.Label(panel, text="CRYPTO COLD WALLET", bg="#081222", fg="#f2f7ff",
                 font=("DejaVu Sans", 24, "bold")).pack()
        tk.Label(panel, text="Secure local wallet", bg="#081222", fg="#65d9ff",
                 font=("DejaVu Sans", 11)).pack(pady=(7, 22))

        tk.Frame(panel, bg="#33476f", height=1, width=280).pack()
        tk.Label(panel, text="By Красимир", bg="#081222", fg="#b7a7ff",
                 font=("DejaVu Sans", 12, "italic")).pack(pady=(16, 0))

        if first_launch:
            tk.Label(
                panel,
                text="Welcome to @Красимир_Cold Wallet",
                bg="#081222", fg="#f2f7ff",
                font=("DejaVu Sans", 14, "bold"),
            ).pack(pady=(22, 8))
            tk.Label(
                panel,
                text=("You are responsible for the assets in your wallet.\n"
                      "No one else can control them without your permission."),
                bg="#081222", fg="#9eabc4", justify="center",
                font=("DejaVu Sans", 10),
            ).pack()
            tk.Label(panel, text="Choose your security level", bg="#081222",
                     fg="#f2f7ff", font=("DejaVu Sans", 13, "bold")).pack(
                         pady=(22, 9))
            tk.Label(panel, text="1) Easy — Convenient",
                     bg="#081222", fg="#54e38e",
                     font=("DejaVu Sans", 11, "bold")).pack()
            tk.Label(panel, text="2) Medium — Recommended",
                     bg="#081222", fg="#ffd166",
                     font=("DejaVu Sans", 11, "bold")).pack(pady=5)
            tk.Label(panel, text="3) Advanced — Maximum compartmentalization",
                     bg="#081222", fg="#ff647c",
                     font=("DejaVu Sans", 11, "bold")).pack()
            tk.Label(
                panel,
                text=("Easy: masterkey at opening; all features available.\n"
                      "Medium: masterkey plus a secondary password for transfers, history and beneficiaries.\n"
                      "Advanced: same secondary password, plus a unique 25-word passphrase for each wallet.\n"
                      "Advanced balance checks ask for 5 random words; revealing keys or signing asks all 25 words.\n"
                      "Lost credentials cannot be recovered. Save them offline and never share them."),
                bg="#081222", fg="#c9d4e8", justify="left",
                font=("DejaVu Sans", 9), wraplength=760,
            ).pack(pady=(16, 0))

        closed = False

        def close(_event=None):
            nonlocal closed
            if not closed:
                closed = True
                root.destroy()

        root.bind("<Escape>", close)
        root.bind("<Return>", close)
        root.bind("<Button-1>", close)
        root.protocol("WM_DELETE_WINDOW", close)
        root.after(15000 if first_launch else duration_ms, close)
        root.deiconify()
        root.lift()
        root.attributes("-topmost", True)
        root.after(150, lambda: root.attributes("-topmost", False))
        root.mainloop()
        return True
    except Exception:
        # Tk absent, DISPLAY indisponible ou image illisible : le portefeuille
        # reste utilisable en SSH/TTY au lieu de bloquer au démarrage.
        return False
