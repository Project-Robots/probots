""" A module for working with security. """

import os

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

VALIDITY: int = 3650  # days
KEY_SIZE: int = 4096  # bits
PUBLIC_EXPONENT: int = 65537  # decimal
RSA_PADDING = None


def load_private_key(private_key_file: str) -> rsa.RSAPrivateKey:
    """Load private key from file."""
    try:
        if os.path.exists(private_key_file):
            with open(private_key_file, "rb") as f:
                return serialization.load_pem_private_key(f.read(), password=None)
        else:
            print(f"Private key file does not exist: {private_key_file}")
            return None
    except Exception as e:
        print(f"Error loading private key: {e}")
        return None


def load_certificate(certificate_file: str) -> x509.Certificate:
    """Load certificate from file."""
    try:
        if os.path.exists(certificate_file):
            with open(certificate_file, "rb") as f:
                return x509.load_pem_x509_certificate(f.read(), default_backend())
        else:
            print(f"Certificate file does not exist: {certificate_file}")
            return None
    except Exception as e:
        print(f"Error loading certificate: {e}")
        return None


def load_csr(csr_file: str) -> x509.CertificateSigningRequest:
    """Load certificate signing request from file."""
    try:
        if os.path.exists(csr_file):
            with open(csr_file, "rb") as f:
                return x509.load_pem_x509_csr(f.read(), default_backend())
        else:
            print(f"Certificate signing request file does not exist: {csr_file}")
            return None
    except Exception as e:
        print(f"Error loading certificate signing request: {e}")
        return None
