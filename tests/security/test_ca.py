""" Unit tests for the CertificateAuthority class. """
import os
import pytest
from unittest import mock
import tests.security as tests
from probots.security.ca import CertificateAuthority

@pytest.fixture
def ca():
  """
  A fixture that returns an instance of CertificateAuthority with the private key file
  and public key file set to 'test_private_key.pem' and 'test_public_key.pem' respectively.
  This fixture is used in tests to create a CertificateAuthority instance which is then
  used to test the methods of the CertificateAuthority class.
  """
  return CertificateAuthority(private_key_file='test_private_key.pem', public_key_file='test_public_key.pem')

def test_load_or_generate_keys_existing(ca):
  """
  Test that load_or_generate_keys calls the load_keys method if the private key
  and public key files exist.

  This test verifies that the load_or_generate_keys method correctly calls the
  load_keys method when both the private key and public key files exist.

  The test sets up a mock for the os.path.exists function which returns True, and
  uses the patch decorator to mock the load_keys method of the CertificateAuthority
  instance. The test then calls the load_or_generate_keys method and verifies that
  the load_keys method was called once.
  """
  with mock.patch('os.path.exists', return_value=True):
    with mock.patch.object(ca, 'load_keys') as mock_load_keys:
      ca.load_or_generate_keys()
      mock_load_keys.assert_called_once()

def test_load_or_generate_keys_generate(ca):
  """
  Test that load_or_generate_keys calls the generate_keys and save_keys methods if the private key
  and public key files do not exist.

  This test verifies that the load_or_generate_keys method correctly calls the
  generate_keys and save_keys methods when both the private key and public key
  files do not exist.

  The test sets up mocks for the os.path.exists, generate_keys, and save_keys
  functions, and then calls the load_or_generate_keys method. The test then
  verifies that the generate_keys and save_keys methods were each called once.
  """ 
  with mock.patch('os.path.exists', side_effect=[False, False]):
    with mock.patch.object(ca, 'generate_keys') as mock_generate_keys:
      with mock.patch.object(ca, 'save_keys') as mock_save_keys:
        ca.load_or_generate_keys()
        mock_generate_keys.assert_called_once()
        mock_save_keys.assert_called_once()

def test_load_keys(ca):
  """
  Test that load_keys calls the load_pem_private_key and load_pem_public_key methods
  with the correct arguments.

  This test verifies that the load_keys method correctly calls the
  load_pem_private_key and load_pem_public_key methods with the correct arguments,
  which are the data read from the private and public key files respectively.

  The test sets up mocks for the builtins.open, load_pem_private_key, and load_pem_public_key
  functions, and then calls the load_keys method. The test then verifies that the
  load_pem_private_key and load_pem_public_key methods were each called once with the
  correct arguments.
  """
  with mock.patch('builtins.open', mock.mock_open(read_data=tests.PRIVATE_KEY)) as mock_open_private:
    with mock.patch('cryptography.hazmat.primitives.serialization.load_pem_private_key') as mock_load_private:
      with mock.patch('builtins.open', mock.mock_open(read_data=tests.PUBLIC_KEY)) as mock_open_public:
        with mock.patch('cryptography.hazmat.primitives.serialization.load_pem_public_key') as mock_load_public:
          ca.load_keys()
          mock_load_private.assert_called_once()
          mock_load_public.assert_called_once()
          
def test_generate_keys(ca):
  """
  Test that generate_keys calls the generate_private_key method with the correct arguments.

  This test verifies that the generate_keys method correctly calls the
  generate_private_key method with the correct arguments, which are the public
  exponent and key size. The test uses the patch decorator to mock the
  generate_private_key method and the public exponent and key size variables,
  and then calls the generate_keys method. The test then verifies that the
  generate_private_key method was called once with the correct arguments.
  """
  with mock.patch('probots.security.PUBLIC_EXPONENT', 65537):
    with mock.patch('probots.security.KEY_SIZE', 2048):
      with mock.patch('cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key') as mock_generate:
        ca.generate_keys()
        mock_generate.assert_called_once()

def test_save_keys(ca):
  """
  Test that save_keys writes the private and public keys to their respective files.

  This test verifies that the save_keys method correctly opens the specified
  private and public key files for writing in binary mode. It uses the patch
  decorator to mock the builtins.open function and then calls the save_keys
  method. The test asserts that the open function is called with the correct
  file names and write mode for both the private and public key files.
  """
  with mock.patch('builtins.open', mock.mock_open()) as mock_open:
    ca.save_keys()
    mock_open.assert_any_call('test_private_key.pem', 'wb')
    mock_open.assert_any_call('test_public_key.pem', 'wb')

def test_get_private_key(ca):
  """
  Test that get_private_key returns the private key attribute.

  This test verifies that the get_private_key method correctly returns the
  private key attribute of the CertificateAuthority instance.

  The test sets up a mock for the private key attribute and then calls the
  get_private_key method. The test then verifies that the returned value is
  equal to the mock object.
  """
  ca.private_key = mock.Mock()
  assert ca.get_private_key() == ca.private_key

def test_get_public_key(ca):
  """
  Test that get_public_key returns the public key attribute.

  This test verifies that the get_public_key method correctly returns the
  public key attribute of the CertificateAuthority instance.

  The test sets up a mock for the public key attribute and then calls the
  get_public_key method. The test then verifies that the returned value is
  equal to the mock object.
  """
  ca.public_key = mock.Mock()
  assert ca.get_public_key() == ca.public_key

def test_sign_csr(ca):
  """
  Test that sign_csr loads a CSR and builds a certificate.

  This test verifies that the sign_csr method of the CertificateAuthority
  instance correctly loads a CSR and uses the CertificateBuilder to build
  a certificate. The test uses the patch decorator to mock the
  load_pem_x509_csr and CertificateBuilder functions, and then calls the
  sign_csr method. It asserts that both the load_pem_x509_csr and
  CertificateBuilder methods are called once during this process.
  """
  mock_csr = tests.CSR
  with mock.patch('cryptography.x509.load_pem_x509_csr') as mock_load_csr:
    with mock.patch('cryptography.x509.CertificateBuilder') as mock_cert_builder:
      ca.sign_csr(mock_csr)
      mock_load_csr.assert_called_once()
      mock_cert_builder.assert_called_once()
            
def teardown_module(module):
  """
  Clean up test environment by removing generated key files.

  This function attempts to remove the 'test_private_key.pem' and
  'test_public_key.pem' files, which are used during testing to
  store temporary private and public keys. If the files do not
  exist or an error occurs during deletion, it silently passes.
  """
  try:
    os.remove('test_private_key.pem')
    os.remove('test_public_key.pem')
  except OSError:
    pass
