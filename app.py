

import sqlite3
import datetime
from flask import Flask, render_template, request, send_file
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509
import os

app = Flask(__name__)
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Mot de passe pour déverrouiller la clé privée
PASSPHRASE = b"BA@!8952026@T_es_t"

# --- GESTION BASE DE DONNÉES (SQLite)  ---
def init_db():
    conn = sqlite3.connect('signatures.db')
    c = conn.cursor()
    # Création table avec Horodatage
    c.execute('''CREATE TABLE IF NOT EXISTS history
                 (id INTEGER PRIMARY KEY, filename TEXT, date_signature TEXT, status TEXT)''')
    conn.commit()
    conn.close()

init_db()

# --- CHARGEMENT CLÉS ---
# 1. Chargement Clé Privée (Avec Mot de Passe) 
with open("keys/private_key_protected.pem", "rb") as f:
    private_key = serialization.load_pem_private_key(
        f.read(),
        password=PASSPHRASE 
    )

# 2. Chargement Clé Publique DEPUIS le Certificat X.509 
with open("keys/certificate.pem", "rb") as f:
    cert = x509.load_pem_x509_certificate(f.read())
    public_key = cert.public_key()

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        file = request.files["file"]
        filename = file.filename
        data = file.read()
        
        # Signature
        signature = private_key.sign(
            data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        
        # Sauvegarde
        sig_path = os.path.join(UPLOAD_FOLDER, "signature.bin")
        with open(sig_path, "wb") as f:
            f.write(signature)
            
        # ENREGISTREMENT EN BDD avec HORODATAGE [cite: 150, 152]
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        conn = sqlite3.connect('signatures.db')
        c = conn.cursor()
        c.execute("INSERT INTO history (filename, date_signature, status) VALUES (?, ?, ?)",
                  (filename, timestamp, "SIGNÉ"))
        conn.commit()
        conn.close()
            
        return send_file(sig_path, as_attachment=True)
        
    # Affichage de l'historique en bas de page
    conn = sqlite3.connect('signatures.db')
    c = conn.cursor()
    c.execute("SELECT * FROM history ORDER BY id DESC")
    historique = c.fetchall()
    conn.close()
    
    return render_template("index.html", history=historique)

@app.route("/verify", methods=["GET", "POST"])
def verify():
    message = None
    if request.method == "POST":
        file = request.files["file"]
        signature_file = request.files["signature"]
        
        # On sauvegarde le nom du fichier pour l'historique
        filename = file.filename
        
        data = file.read()
        sig = signature_file.read()
        
        # Variable pour le statut en BDD
        db_status = ""
        
        try:
            public_key.verify(
                sig,
                data,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            message = "✅ VALIDE (Vérifié via Certificat X.509)"
            db_status = "VERIF OK" # On note que la vérification a réussi
            
        except Exception:
            message = "❌ NON VALIDE"
            db_status = "ECHEC VERIF" # On note que c'était une fausse signature
            
        # --- ENREGISTREMENT DE LA TENTATIVE DE VÉRIFICATION EN BDD ---
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        conn = sqlite3.connect('signatures.db')
        c = conn.cursor()
        # On insère l'événement dans la table history
        c.execute("INSERT INTO history (filename, date_signature, status) VALUES (?, ?, ?)",
                  (filename, timestamp, db_status))
        conn.commit()
        conn.close()
            
    return render_template("verify.html", message=message)

if __name__ == "__main__":
    app.run(debug=True)