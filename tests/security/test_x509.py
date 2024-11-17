""" Unit tests for the x509 module. """
import pytest
from unittest import mock
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import CertificateSigningRequest, Certificate
from cryptography.x509.oid import NameOID
from probots.security.x509 import X509Certificate
from probots.security.ca import CertificateAuthority

@pytest.fixture
def x509_certificate():
  """Fixture for creating an instance of X509Certificate."""
  subject_oids = {
    "COMMON_NAME": "example.com",
    "COUNTRY_NAME": "US",
    "ORGANIZATION_NAME": "Example Inc."
  }
  subject_alt_names = ["www.example.com", "api.example.com"]
  return X509Certificate(subject_oids, subject_alt_names)

def test_create_csr(x509_certificate):
  """Test the creation of a CSR."""
  csr = x509_certificate.create_csr()
  assert isinstance(csr, CertificateSigningRequest)
  assert x509_certificate.private_key is not None

def test_save_private_key(x509_certificate, tmp_path):
  """Test saving the private key to a file."""
  x509_certificate.create_csr()
  file_path = tmp_path / "private_key.pem"
  x509_certificate.save_private_key(file_path)
  assert file_path.is_file()

def test_save_csr(x509_certificate, tmp_path):
  """Test saving the CSR to a file."""
  x509_certificate.create_csr()
  file_path = tmp_path / "csr.pem"
  x509_certificate.save_csr(file_path)
  assert file_path.is_file()

def test_save_certificate_success(x509_certificate, tmp_path):
  """Test saving a valid certificate."""
  x509_certificate.create_csr()
  mock_cert = mock.Mock()
  mock_cert.public_key.return_value.verify.return_value = None
  mock_cert.public_bytes.return_value = b"mock_certificate_data"
  file_path = tmp_path / "certificate.pem"
  x509_certificate.save_certificate(mock_cert, file_path)
  assert file_path.is_file()
  
