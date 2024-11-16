""" This module provides unit tests for the ca module. """

import os
import pytest
from unittest import mock
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timedelta
import pytz
from probots.security.ca import CertificateAuthority, get_default_ca_paths

@pytest.fixture
def ca():
    """ Fixture to create a CertificateAuthority instance. """
    return CertificateAuthority(
        country="US",
        state="California",
        locality="Placentia",
        organization="Project Robots",
        organizational_unit="Engineering",
        common_name="orbit.local"
    )

@pytest.fixture
def fake_ca_paths(tmp_path):
    """Fixture to mock default paths with a temporary path."""
    with mock.patch("os.geteuid", return_value=1000):  # simulate non-root user
        yield get_default_ca_paths("test_robot")

def test_get_default_ca_paths_root():
    """Test get_default_ca_paths with root user."""
    with mock.patch("os.geteuid", return_value=0):
        paths = get_default_ca_paths("test_robot")
        assert paths["private_key_path"] == "/etc/test_robot/ca/private_key.pem"
        assert paths["certificate_path"] == "/etc/test_robot/ca/cacert.pem"

def test_get_default_ca_paths_non_root():
    """Test get_default_ca_paths with non-root user."""
    with mock.patch("os.geteuid", return_value=1000):
        paths = get_default_ca_paths("test_robot")
        assert paths["private_key_path"].endswith("/.test_robot/ca/private_key.pem")
        assert paths["certificate_path"].endswith("/.test_robot/ca/cacert.pem")

def test_load_or_generate_ca_existing_files(ca, tmp_path):
    """Test _load_or_generate_ca loads existing files."""
    private_key_path = tmp_path / "private_key.pem"
    certificate_path = tmp_path / "cacert.pem"

    # Generate and save CA key and certificate
    ca._generate_ca()
    with open(private_key_path, "wb") as key_file, open(certificate_path, "wb") as cert_file:
        key_file.write(ca.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
        cert_file.write(ca.certificate.public_bytes(serialization.Encoding.PEM))

    ca._load_or_generate_ca()
    assert ca.private_key is not None
    assert ca.certificate is not None

def test_generate_ca(ca):
    """Test CA generation and validity of the generated certificate."""
    ca._generate_ca()
    assert ca.private_key is not None
    assert ca.certificate is not None
    assert ca.certificate.not_valid_before_utc < datetime.now(pytz.UTC)
    assert ca.certificate.not_valid_after_utc > datetime.now(pytz.UTC)

def test_sign_csr(ca):
    """Test signing a CSR with CA."""
    ca._generate_ca()

    # Generate a CSR to be signed
    csr_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "test.local")]))
        .sign(private_key=csr_private_key, rsa_padding=padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), algorithm=hashes.SHA256(), backend=default_backend())
    )

    signed_cert = ca.sign_csr(csr)
    assert signed_cert.issuer == ca.certificate.subject
    assert signed_cert.not_valid_before_utc < datetime.now(pytz.UTC)
    assert signed_cert.not_valid_after_utc > datetime.now(pytz.UTC)

def test_get_ca_certificate(ca):
    """Test get_ca_certificate method."""
    ca._generate_ca()
    cert = ca.get_ca_certificate()
    assert cert == ca.certificate

def test_verify_certificate(ca):
    """Test verify_certificate with a valid certificate."""
    ca._generate_ca()
    cert = ca.get_ca_certificate()
    assert ca.verify_certificate(cert) is True

def test_verify_certificate_invalid_signature(ca):
    """Test verify_certificate with an invalid certificate."""
    ca._generate_ca()

    # Generate a CSR and sign with a different key to create a mismatched certificate
    csr_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = (x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "test.local")]))
        .sign(private_key=csr_private_key, rsa_padding=padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), algorithm=hashes.SHA256(), backend=default_backend())
    )
    mismatched_cert = ca.sign_csr(csr)

    # Try verifying mismatched certificate
    assert ca.verify_certificate(mismatched_cert) is False

def test_verify_csr(ca):
    """Test CSR verification."""
    ca._generate_ca()
    private_key = ca.private_key
    
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "test.local")]))
        .sign(private_key=private_key, rsa_padding=padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), algorithm=hashes.SHA256(), backend=default_backend())
    )
    assert ca.verify_csr(csr) is True

def test_verify_csr_invalid_signature(ca):
    """Test verify_csr with an invalid signature."""
    ca._generate_ca()
    csr_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "test.local")]))
        .sign(csr_private_key, hashes.SHA256())
    )

    # Tamper with the CSR to make the signature invalid
    tampered_csr = csr.public_bytes(serialization.Encoding.PEM) + b"tampered"
    tampered_csr = x509.load_pem_x509_csr(tampered_csr)

    assert ca.verify_csr(tampered_csr) is False