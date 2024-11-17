"""
This module provides a Certificate Authority (CA) class for generating and managing private and public keys.
"""
from math import e
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509
from datetime import datetime, timedelta
from pytz import utc

import probots.security as security

class CertificateAuthority:
  """
  A Certificate Authority (CA) class for generating and managing private and public keys.
  """
  def __init__(self, private_key_file='private_key.pem', public_key_file='public_key.pem'):
    """
    Initialize a CertificateAuthority instance.

    This constructor initializes a CertificateAuthority instance by setting
    the private and public key file paths. It also initializes the private key
    and public key attributes to None. The load_or_generate_keys method is
    then called to load existing keys or generate new ones if none exist.

    Args:
        private_key_file: The path to the private key file. Defaults to 'private_key.pem'.
        public_key_file: The path to the public key file. Defaults to 'public_key.pem'.
    """
    self.private_key_file = private_key_file
    self.public_key_file = public_key_file
    self.private_key = None
    self.public_key = None
    self.load_or_generate_keys()

  def load_or_generate_keys(self):
    """
    Load or generate the private and public keys.

    This method checks if both the private and public key files exist. If
    they do, it calls the load_keys method to load the existing keys. If
    not, it calls the generate_keys method to generate new keys and then
    saves them with the save_keys method.
    """
    if os.path.exists(self.private_key_file) and os.path.exists(self.public_key_file):
        self.load_keys()
    else:
        self.generate_keys()
        self.save_keys()

  def load_keys(self):
    """
    Load the private and public keys from their respective files.

    This method opens the specified private and public key files and loads
    the keys using the PEM serialization format. If the keys are successfully
    loaded, they are assigned to the `private_key` and `public_key` attributes
    of the CertificateAuthority instance.

    Raises:
        ValueError: If the provided file is not a valid PEM-encoded key.
        TypeError: If the data is incorrectly formatted or the key is encrypted.
        FileNotFoundError: If the specified key files do not exist.
    """
    with open(self.private_key_file, 'rb') as f:
      self.private_key = serialization.load_pem_private_key(
        data=f.read(),
        password=None,
        backend=default_backend()
      )
    with open(self.public_key_file, 'rb') as f:
      self.public_key = serialization.load_pem_public_key(
        data=f.read(),
        backend=default_backend()
      )

  def generate_keys(self):
    """
    Generate new private and public keys.

    This method generates a new private and public key pair using the
    `cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key`
    function. The private and public keys are then saved to the respective
    files specified in the constructor.

    Raises:
        TypeError: If the generated key is not a valid RSA key.

    """
    self.private_key = rsa.generate_private_key(
      public_exponent=security.PUBLIC_EXPONENT,
      key_size=security.KEY_SIZE,
      backend=default_backend()
    )
    self.public_key = self.private_key.public_key()

  def save_keys(self):
    """
    Save the private and public keys to their respective files.

    This method writes the private and public keys to the files specified
    in the constructor using the PEM serialization format. The private key
    is saved in the Traditional OpenSSL format, while the public key is
    saved in the SubjectPublicKeyInfo format.

    Raises:
        TypeError: If the private or public key cannot be serialized to PEM.
        ValueError: If the specified key format is not supported.
    """
    with open(self.private_key_file, 'wb') as f:
      f.write(self.private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
      ))
      
    with open(self.public_key_file, 'wb') as f:
      f.write(self.public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
      ))

  def get_private_key(self):
    """
    Return the private key as a cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey object.

    Returns:
        RSAPrivateKey: The private key.
    """
    return self.private_key

  def get_public_key(self):
    """
    Return the public key as a cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey object.

    Returns:
        RSAPublicKey: The public key.
    """
    return self.public_key
      
  def sign_csr(self, csr):
    """
    Sign a Certificate Signing Request (CSR) with the CA's private key.

    Args:
        csr: The Certificate Signing Request (CSR) as a PEM-encoded string.

    Returns:
        A PEM-encoded string containing the signed certificate.

    Raises:
        TypeError: If the CSR is not a PEM-encoded string.
        ValueError: If the CSR cannot be loaded as a cryptography.x509.CertificateSigningRequest.
    """
    # Load the CSR
    csr_obj = x509.load_pem_x509_csr(csr, default_backend())

    # Create a self-signed certificate
    subject = csr_obj.subject
    issuer = subject  # Self-signed
    cert = (
      x509.CertificateBuilder()
      .subject_name(subject)
      .issuer_name(issuer)
      .public_key(csr_obj.public_key())
      .serial_number(x509.random_serial_number())
      .not_valid_before(datetime.now(tz=utc))
      .not_valid_after(datetime.now(tz=utc) + timedelta(days=security.VALIDITY))  # Valid for 1 year
      .sign(
        private_key=self.private_key,
        algorithm=hashes.SHA256(),
        padding=padding.PSS(
          mgf=padding.MGF1(
            algorithm=hashes.SHA256()
          ),
          salt_length=padding.PSS.MAX_LENGTH
        ),
        backend=default_backend()
      )
    )    
    # Return the certificate in PEM format
    return cert.public_bytes(serialization.Encoding.PEM)
    
