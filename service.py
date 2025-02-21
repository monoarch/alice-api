from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta

# 1. Generate private key for CA
ca_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

# 2. Build CA subject name
ca_name = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"MyState"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, u"MyCity"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"MyOrg"),
    x509.NameAttribute(NameOID.COMMON_NAME, u"My Root CA"),
])

# 3. Create a self-signed certificate for the CA
ca_cert = (
    x509.CertificateBuilder()
    .subject_name(ca_name)
    .issuer_name(ca_name)  # self-signed, so issuer is the same as subject
    .public_key(ca_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.utcnow())
    .not_valid_after(datetime.utcnow() + timedelta(days=3650))  # 10-year expiry
    .add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True
    )
    .sign(private_key=ca_key, algorithm=hashes.SHA256(), backend=default_backend())
)

# 4. (Optional) Save the CA cert/key to files
with open("my_root_ca_key.pem", "wb") as f:
    f.write(
        ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),  # or use a passphrase
        )
    )

with open("my_root_ca_cert.pem", "wb") as f:
    f.write(
        ca_cert.public_bytes(encoding=serialization.Encoding.PEM)
    )


# Suppose we have the CA key and CA cert loaded from above
# Now generate a private key for the user’s certificate:
user_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

# Build a subject name for the user. 
# Let's say we store "Alice" in the Common Name (CN).
user_subject = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),  # or appropriate values
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"MyState"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, u"MyCity"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"MyOrg"),
    x509.NameAttribute(NameOID.COMMON_NAME, u"Alice"),
])

# Build an X.509 Certificate for the user
user_cert_builder = x509.CertificateBuilder().subject_name(
    user_subject
).issuer_name(
    ca_cert.subject  # Issued by our CA
).public_key(
    user_key.public_key()
).serial_number(
    x509.random_serial_number()
).not_valid_before(
    datetime.datetime.now(datetime.UTC)
).not_valid_after(
    # Set certificate validity, e.g. 1 year
    datetime.datetime.now(datetime.UTC) + timedelta(days=365)
).add_extension(
    # Typically for end-entity certs, you might not set path_length
    x509.BasicConstraints(ca=False, path_length=None),
    critical=True,
)

# Sign the user's certificate using the CA's private key
user_cert = user_cert_builder.sign(
    private_key=ca_key,
    algorithm=hashes.SHA256(),
    backend=default_backend()
)

# (Optional) Save the user’s certificate and private key to files
with open("alice_key.pem", "wb") as f:
    f.write(
        user_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

with open("alice_cert.pem", "wb") as f:
    f.write(
        user_cert.public_bytes(encoding=serialization.Encoding.PEM)
    )
