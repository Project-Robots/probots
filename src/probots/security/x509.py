""" X509 module."""
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.x509 import Name, NameAttribute, Certificate, CertificateSigningRequestBuilder, DNSName, SubjectAlternativeName
from cryptography.x509.oid import NameOID

import probots.security as security

class X509Certificate:
  """ X509Certificate class. """
  def __init__(self, subject_oids, subject_alt_names):
    """
    Initialize a X509Certificate instance.

    This constructor initializes a X509Certificate instance by setting the
    subject OIDs and subject alternative names. It also initializes the
    private key and certificate signing request (CSR) attributes to None.

    Args:
      subject_oids: A dictionary of subject OIDs and their corresponding
          values.
      subject_alt_names: A list of subject alternative names.
    """
    self.subject_oids = subject_oids
    self.subject_alt_names = subject_alt_names
    self.private_key = None
    self.csr = None

  def create_csr(self):
    """
    Create a certificate signing request (CSR) using the subject OIDs and
    subject alternative names.

    This method generates a private key and a certificate signing request
    (CSR) using the subject OIDs and subject alternative names. The CSR is
    then signed with the private key.

    Returns:
      The certificate signing request (CSR).
    """
    # Generate private key
    self.private_key = rsa.generate_private_key(
        public_exponent=security.PUBLIC_EXPONENT,
        key_size=security.KEY_SIZE,
        backend=default_backend()
    )

    # Create CSR
    subject = [NameAttribute(NameOID.COMMON_NAME, self.subject_oids.get("COMMON_NAME", "localhost.localdomain"))]
    for oid, value in self.subject_oids.items():
      if oid != "COMMON_NAME":
        subject.append(NameAttribute(getattr(NameOID, oid), value))

    self.csr = CertificateSigningRequestBuilder().subject_name(Name(subject)).add_extension(
        SubjectAlternativeName([DNSName(name) for name in self.subject_alt_names]), critical=False
    ).sign(self.private_key, hashes.SHA256(), default_backend())

    return self.csr

  def save_private_key(self, file_path):
    """
    Save the private key to the given file path.

    This method saves the private key in the given file path in PEM format.
    The private key is saved in the Traditional OpenSSL format with no
    encryption.

    Args:
        file_path: The file path to save the private key to.
    """
    with open(file_path, "wb") as key_file:
      key_file.write(self.private_key.private_bytes(
      encoding=serialization.Encoding.PEM,
      format=serialization.PrivateFormat.TraditionalOpenSSL,
      encryption_algorithm=serialization.NoEncryption()
    ))

  def save_csr(self, file_path):
    """
    Save the certificate signing request (CSR) to the given file path.

    This method saves the certificate signing request (CSR) in the given
    file path in PEM format.

    Args:
        file_path: The file path to save the CSR to.
    """
    with open(file_path, "wb") as csr_file:
      csr_file.write(self.csr.public_bytes(serialization.Encoding.PEM))

  def save_certificate(self, certificate: Certificate = None, file_path: str = None):
    """
    Save a certificate to the given file path.

    This method saves the given certificate in the given file path in PEM format.
    The certificate is verified against the private key before being saved. If
    the verification fails, a ValueError is raised.

    Args:
        certificate: The certificate to save.
        file_path: The file path to save the certificate to.
    """
    with open(file_path, "wb") as cert_file:
      cert_file.write(certificate.public_bytes(serialization.Encoding.PEM))