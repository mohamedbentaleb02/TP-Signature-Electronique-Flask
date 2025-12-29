import datetime
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID


PASSPHRASE = b"BA@!8952026@T_es_t"  


private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)


with open("keys/private_key_protected.pem", "wb") as f:
    f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.BestAvailableEncryption(PASSPHRASE) 
    ))

# 3. Création du Certificat X.509 (Auto-signé) 
subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"MA"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"TP"),
    x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
])

cert = x509.CertificateBuilder().subject_name(
    subject
).issuer_name(
    issuer
).public_key(
    private_key.public_key()
).serial_number(
    x509.random_serial_number()
).not_valid_before(
    datetime.datetime.utcnow()
).not_valid_after(
    # Valide pour 10 jours
    datetime.datetime.utcnow() + datetime.timedelta(days=10)
).add_extension(
    x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
    critical=False,
).sign(private_key, hashes.SHA256())

# Sauvegarde du certificat (qui contient la clé publique)
with open("keys/certificate.pem", "wb") as f:
    f.write(cert.public_bytes(serialization.Encoding.PEM))

print("✅ Clés et Certificat X.509 générés avec succès.")