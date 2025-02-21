from datetime import datetime, timedelta
import os
import uuid

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///documentation.db'
app.config['UPLOAD_FOLDER'] = 'uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
db = SQLAlchemy(app)

# TODO: read key from somewhere
ca_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

# TODO: fix
def certify():
    user_public_key = serialization.load_pem_public_key(
        request.form.get('public_key'),
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
        user_public_key
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

class PublicKey(db.Model):
    id = db.Column(db.String(36), primary_key=True)
    key = db.Column(db.Text, nullable=False)

class Documentation(db.Model):
    id = db.Column(db.String(36), db.ForeignKey('public_key.id'), primary_key=True)
    license_front = db.Column(db.String(255), nullable=False)
    license_back = db.Column(db.String(255), nullable=False)
    headshot = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(20), nullable=False, default='pending')

@app.before_first_request
def create_tables():
    db.create_all()

@app.route('/submit_documentation', methods=['POST'])
def submit_documentation():
    if 'license_front' not in request.files or 'license_back' not in request.files or 'headshot' not in request.files:
        return jsonify({'error': 'Missing required image files.'}), 400
    
    public_key = request.form.get('public_key')
    if not public_key:
        return jsonify({'error': 'Public key is required.'}), 400

    user_id = str(uuid.uuid4())
    
    # Save public key
    new_key = PublicKey(id=user_id, key=public_key)
    db.session.add(new_key)

    # Save images
    file_paths = {}
    for image_name in ['license_front', 'license_back', 'headshot']:
        file = request.files[image_name]
        filename = f"{user_id}_{image_name}_{file.filename}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        file_paths[image_name] = filepath

    # Save documentation info
    new_doc = Documentation(
        id=user_id,
        license_front=file_paths['license_front'],
        license_back=file_paths['license_back'],
        headshot=file_paths['headshot'],
        status='pending'
    )
    db.session.add(new_doc)
    db.session.commit()

    return jsonify({'id': user_id}), 200

@app.route('/check_status/<string:user_id>', methods=['GET'])
def check_status(user_id):
    doc = Documentation.query.filter_by(id=user_id).first()
    if not doc:
        return jsonify({'error': 'Documentation not found.'}), 404
    return jsonify({'status': doc.status}), 200

if __name__ == '__main__':
    app.run(debug=True)
