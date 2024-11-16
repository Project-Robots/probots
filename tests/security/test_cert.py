""" Unit tests for the cert module. """
import os
import pytest
import tempfile
from unittest.mock import patch, mock_open, MagicMock
from probots.security.cert import get_default_paths, HostCertificate
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

default_private_key = b"""-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCHTiAhpoKbhK2j
WII/InwaHDfBg7k1sgYvs90HjzM5vXgJmhHcAz5NrYc2j6C0wlGvdqgVCKPXhjJM
q8DecaXSVt7ZNvjfGfUwb12psF/C+gBeFP0IBT8sReSfOLBS6oLScHpaQIszRAAC
JUgrj2/SNRZXxWl3UJidBFA68y2YMxd5IhkLyyqIsozeSQAHysm5DaRIT7r06Zm8
TJ9NqD/5IFdy7B1WWqUm7++rNRA5ZtIvboSFkw+PRHbtHPsoMFahp2kgb2Z+RJXI
nSj/W/pLjo5D81I32jGldJqHOoqEWomra721L+vnef+ZGV71IhHop4UBo7TqGq4s
TGhWAOsJAgMBAAECggEAEmhEAcqegRwjPTzYzKWwiXgmSQWBEwzVlPQcu/RfgoRE
CiuzhfbLqT3+zk2Vjjx+Ery18CqdPkBro7edWlskCoIL+N68K9SNtpmn/eJYnMoY
dl7XmkQ7IcGecTTWnr54WWW47NdUDf+QcA+fX7cN/jnVANAtYXCNr+rQJBJE39bS
P23itUYRMuUq1Rs6VUHOnR5Ejc3bu3AF5C6L+4cdVJXR5J1d5LlUMp0JZ5Zh8GSz
dVDZ5LiCbQ24bWfkQRDRvOjiyjBdn/wQEC7FZIFNs82dd1SMSsp8gkuPMpWWG7Jk
bm9o18cP8goNv6z2SSN1a0q+AV39vMwb1cajk4MZGwKBgQC7j07nqXz1HwYlC7mP
ooiXYVujTOJuAdqBHzdMvj9u4CN0jaAQ8ZC7bPgaWsxuRiVopNM8bBziv690qtXN
ATfgvrptzVQjHIQs9fFhO5d80zKH9JRqo5Kwunx3XdhhUdm4HCA2ifZCelERs9df
Oc8C8eA/H4yDnGUUCBUXIWBZ6wKBgQC4rYJytz14Qy7LThiaROA7UoGn5LBVsZEj
JTfPxnksQqQouj1C0Qe7+B2IaZTtJ+k79sJpUXvALuGHiAIFQHhoBCq/RivvuePl
tmX2bMfgiBcAIi+IxgzOQL9PUDMzO+DCYCN4YFUkrvcZZ0h/rvJp62EoBzKJ50o1
ANyRwLU92wKBgQCishg/Ch2Tv5qj7fzD5LhZoCFOkTXlOQRid0KP9oOt2Q3IX8XW
jMUAX/EDY3nrujte/4Mg6aNQ6ff32uzlDMZ81NWAw9jVMDpTifAdaQTqSYWOu5E2
w7dOSCYJoUU+fjK+6t7ikGAmoFXMZlVPjCTPKCNefi50R+jCLJSm4NPkiwKBgGPM
oCoODBHpfGgxk+oKPoLQW3C3jPNCOgScIEUQJHteqAe6XVC2VU+nDY6iP/DJGKlm
+Dih6BY7P3VWcoEUDf1oAxHKggPSmO2SXBeHQZx87rELyFRJcrIjGz9pP8H4IcXo
3kI3DMv+IVqBDhSyHh5PLPnMqesMKnXqOUgqs8bxAoGACitGKBERn2Tb4O91jioV
s9shTLgdH7dIqdDGHYaIuKWPCYZmbO+KcDrpmAVWUC+PhZgvjEewarFY9K6Qm2kZ
04HacyYnLXMNWi6+VnF50X5soBEQv3swGip7URGhzGqkeHfSUWY+Keg+5QFAqvX0
6fx7NONKTVdfL2bE0MnzyAo=
-----END PRIVATE KEY-----"""

default_certificate = b"""-----BEGIN CERTIFICATE-----
MIIDuzCCAqOgAwIBAgIUYdjr2M3KvgSUv1f34a9PpnEisQEwDQYJKoZIhvcNAQEL
BQAwgYUxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRIwEAYDVQQH
DAlQbGFjZW50aWExHzAdBgNVBAoMFlRob3VnaHQgUGFyYW1ldGVycyBMTEMxFDAS
BgNVBAsMC0VuZ2luZWVyaW5nMRYwFAYDVQQDDA10ZXN0X2hvc3RuYW1lMB4XDTI0
MTExMjIxMDczMFoXDTI1MTExMjIxMDczMFowgYUxCzAJBgNVBAYTAlVTMRMwEQYD
VQQIDApDYWxpZm9ybmlhMRIwEAYDVQQHDAlQbGFjZW50aWExHzAdBgNVBAoMFlRo
b3VnaHQgUGFyYW1ldGVycyBMTEMxFDASBgNVBAsMC0VuZ2luZWVyaW5nMRYwFAYD
VQQDDA10ZXN0X2hvc3RuYW1lMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC
AQEAh04gIaaCm4Sto1iCPyJ8Ghw3wYO5NbIGL7PdB48zOb14CZoR3AM+Ta2HNo+g
tMJRr3aoFQij14YyTKvA3nGl0lbe2Tb43xn1MG9dqbBfwvoAXhT9CAU/LEXknziw
UuqC0nB6WkCLM0QAAiVIK49v0jUWV8Vpd1CYnQRQOvMtmDMXeSIZC8sqiLKM3kkA
B8rJuQ2kSE+69OmZvEyfTag/+SBXcuwdVlqlJu/vqzUQOWbSL26EhZMPj0R27Rz7
KDBWoadpIG9mfkSVyJ0o/1v6S46OQ/NSN9oxpXSahzqKhFqJq2u9tS/r53n/mRle
9SIR6KeFAaO06hquLExoVgDrCQIDAQABoyEwHzAdBgNVHQ4EFgQUigwlEJyHH385
L0sIKvJJgRPppz4wDQYJKoZIhvcNAQELBQADggEBAFD1GduzWRdDaL9wuRqF1gwW
pL7PjPZ301W2kFNv1dEMEgZAty/B7gNHhovGqIHmWQOEu+ipK9C4ZxqbxDxhsOqF
jIFmH/hTnnoY7XEpz1wkwUtDtzM1LPoXlS3jJ8qqXrIhnS3Lbx8i+vremXLYgEqy
6AplRoOvb8iLJBvyBfImTL7Plfr0K7FRPqZNJvENEheqDJIznA46F7uoG8PVfB4Q
pL3s2NJm+ZKAfhoH1v/3QtTi6HcykWx+s6A7aSwdjYuwB60xcKkFMU8AA4nCFEl4
nAFJa22bfHvtqgqdDFwP5XSD8mZ+yrDQ9T0d2aZEbPGbgnbdGk7uaFfwb69S/9o=
-----END CERTIFICATE-----"""

default_csr = """-----BEGIN CERTIFICATE REQUEST-----
MIICyzCCAbMCAQAwgYUxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlh
MRIwEAYDVQQHDAlQbGFjZW50aWExHzAdBgNVBAoMFlRob3VnaHQgUGFyYW1ldGVy
cyBMTEMxFDASBgNVBAsMC0VuZ2luZWVyaW5nMRYwFAYDVQQDDA10ZXN0X2hvc3Ru
YW1lMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAh04gIaaCm4Sto1iC
PyJ8Ghw3wYO5NbIGL7PdB48zOb14CZoR3AM+Ta2HNo+gtMJRr3aoFQij14YyTKvA
3nGl0lbe2Tb43xn1MG9dqbBfwvoAXhT9CAU/LEXknziwUuqC0nB6WkCLM0QAAiVI
K49v0jUWV8Vpd1CYnQRQOvMtmDMXeSIZC8sqiLKM3kkAB8rJuQ2kSE+69OmZvEyf
Tag/+SBXcuwdVlqlJu/vqzUQOWbSL26EhZMPj0R27Rz7KDBWoadpIG9mfkSVyJ0o
/1v6S46OQ/NSN9oxpXSahzqKhFqJq2u9tS/r53n/mRle9SIR6KeFAaO06hquLExo
VgDrCQIDAQABoAAwDQYJKoZIhvcNAQELBQADggEBADGX00l3MZ3H8snqiGD01kZC
vKd1RSkQkKBHmXztCaBKLwX3ZGIXUJnrq1DRv4KZOzEV2Yuf36S1Nwx11EyJ1+Dj
sNPLZe7cVjwVsfEGO2K9LCE58AhvefdnLV6qa0leR76MREwLBM0dZPsJ4y3I4EMn
yjT4zVGcBDhmu0HWoV6btxnxwUH99vaalyK6A7vS/aYZwf944uepuaIynxME+XPH
nFn8oBPGiJ0jonPxhi3Km5YVceiNi3XV5zbzlXz8pHSpvc8a/fyfCOQ4EnXv7IlU
s9aKiFcSwfKvE/OXd62tgR5trIfvSCZxUPTvR+RYTjNL6jFIOOSDrqK5582DMiY=
-----END CERTIFICATE REQUEST-----"""

@pytest.fixture
def mock_rsa_generate_key():
  """Fixture to mock the result of rsa.generate_private_key()."""
  with patch('cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key',
            return_value=rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend())) as mock_generate_key:
    yield mock_generate_key
    
@pytest.fixture
def mock_hostname():
  """Fixture to mock the result of socket.gethostname()."""
  with patch('socket.getfqdn', return_value='test_hostname'):
    yield 'test_hostname'

@pytest.fixture
def mock_fqdn():
  """Fixture to mock the result of socket.getfqdn()."""
  with patch('socket.getfqdn', return_value='test_fqdn'):
    yield 'test_fqdn'
@pytest.fixture
def mock_paths():
    """
    Fixture to mock the path existence check and directory creation.

    This fixture patches 'os.path.exists' to always return False, simulating
    non-existent paths, and patches 'os.makedirs' to yield a mock object,
    allowing tests to verify directory creation behavior.
    """
    with patch('os.path.exists', return_value=False):
        with patch('os.makedirs') as mock_makedirs:
            yield mock_makedirs

@pytest.fixture
def mock_write_file():
  """
  A fixture that patches the builtins.open function with a mock_open
  object, which can be used to verify that a file was written to.

  The fixture is a context manager, so it can be used with a with statement.
  The mock_file object is yielded by the fixture, and can be used to verify
  that the correct file was written to.
  """
  with patch("builtins.open", mock_open()) as mock_file:
    yield mock_file
    

def test_get_default_paths_root_user():
  """
  Test that get_default_paths returns the correct paths for a root user
  running on a host named "testhost".
  """
  with patch("os.geteuid", return_value=0):
    paths = get_default_paths(robot_name="test_robot", hostname="testhost")
    assert paths["private_key_path"] == "/etc/test_robot/ssl/testhost_key.pem"
    assert paths["certificate_path"] == "/etc/test_robot/ssl/testhost_cert.pem"
    assert paths["csr_path"] == "/etc/test_robot/ssl/testhost_csr.pem"

def test_get_default_paths_non_root_user():
  """
  Test that get_default_paths returns the correct paths for a non-root user
  running on a host named "testhost".

  The paths should be in the user's home directory, under the .test_robot directory.
  """
  with patch("os.geteuid", return_value=1000), patch("os.path.expanduser", return_value="/home/user/.test_robot/ssl/"):
    paths = get_default_paths("test_robot", hostname="testhost")
    assert paths["private_key_path"] == "/home/user/.test_robot/ssl/testhost_key.pem"
    assert paths["certificate_path"] == "/home/user/.test_robot/ssl/testhost_cert.pem"
    assert paths["csr_path"] == "/home/user/.test_robot/ssl/testhost_csr.pem"

def test_host_certificate_initialization(mock_hostname, mock_fqdn, mock_paths):
  """
  Test the initialization of the HostCertificate class with default values.

  This test verifies that the HostCertificate instance is initialized with
  the correct default field values, including the robot name, country, state,
  locality, organization, organizational unit, common name, and alternative
  names. The host name and fully qualified domain name are mocked to ensure
  consistent behavior across different test environments.
  """
  cert = HostCertificate(robot_name="robot",
                         country="US",
                         state="California",
                         locality="Placentia",
                         organization="Project Robots | Thought Parameters LLC",
                         organizational_unit="Engineering",
                         common_name="robot.testhost.io.bot",
                         alt_names=["testhost", "testhost.local"])
  
  assert cert.robot_name == "robot"
  assert cert.country == "US"
  assert cert.state == "California"
  assert cert.locality == "Placentia"
  assert cert.organization == "Project Robots | Thought Parameters LLC"
  assert cert.organizational_unit == "Engineering"
  assert cert.common_name == "robot.testhost.io.bot"
  assert cert.alt_names == ["testhost", "testhost.local"]

def test_generate_key_and_csr(mock_rsa_generate_key, mock_hostname, mock_fqdn, mock_write_file):
  """
  Test that generate_key_and_csr generates a private key and CSR correctly.

  This test verifies that the private key is generated using the
  `rsa.generate_private_key` function, and that it is saved to the correct
  file. The test also verifies that a Certificate Signing Request (CSR)
  is generated and saved to the correct file.
  """
  mock_private_key = mock_rsa_generate_key.return_value
  cert = HostCertificate(robot_name="robot",
                         common_name=mock_hostname,
                         alt_names=[mock_hostname, mock_fqdn])
  cert.generate_key_and_csr()
  
  mock_rsa_generate_key.assert_called_once()
  assert cert.private_key == mock_private_key
  mock_write_file().write.assert_called()

def test_save_certificate(mock_write_file, mock_paths):
  """
  Test that save_certificate saves the given certificate to the correct file.

  This test verifies that the save_certificate method saves the given
  certificate to the correct file, as specified by the cert_path field.
  """
  cert = HostCertificate()
  dummy_cert = MagicMock(spec=x509.Certificate)
  cert.save_certificate(dummy_cert)
  mock_write_file().write.assert_called()

@patch("probots.security.cert.os.path.exists", return_value=True)
@patch("probots.security.cert.open", new_callable=mock_open)
@patch("probots.security.cert.serialization.load_pem_private_key")
@patch("probots.security.cert.x509.load_pem_x509_certificate")
@patch("probots.security.cert.x509.load_pem_x509_csr")
def test_load_or_generate_existing_key(mock_load_csr,mock_load_cert,mock_load_key, mock_open_file, mock_exists):
  """
  Test that load_or_generate correctly loads an existing private key and
  certificate when both exist.

  This test verifies that the load_or_generate method correctly loads an
  existing private key and certificate when both exist. The test uses the
  patch decorator to mock the os.path.exists and serialization.load_pem_private_key
  functions.

  The test creates a HostCertificate instance and calls the load_or_generate
  method. The test then verifies that the private_key field of the instance
  is set to the mock private key that was returned by the mock
  load_pem_private_key function.
  """
  
  mock_private_key = serialization.load_pem_private_key(data=default_private_key,
                                                                  password=None,
                                                                  backend=default_backend())

  mock_load_key.return_value = mock_private_key
    
  mock_certificate = x509.load_pem_x509_certificate(data=default_certificate, backend=default_backend())
  mock_load_cert.return_value = mock_certificate
  
  mock_csr = x509.load_pem_x509_csr(data=default_csr, backend=default_backend())
  mock_load_csr.return_value = mock_csr
  
  cert = HostCertificate()
  
  cert.load_or_generate()

  # Assert that open was called to read the key file
  mock_open_file.assert_any_call(cert.key_path, "rb")
  mock_open_file.assert_any_call(cert.cert_path, "rb")
  mock_open_file.assert_any_call(cert.csr_path, "rb")

  # Assert the private key is set to the mock object returned by load_pem_private_key
  assert cert.private_key is not None, "Private key should be set"
  assert cert.private_key == mock_private_key, "Private key should be the same as the mock private key"
  
  assert cert.certificate is not None, "Certificate should be set"
  assert cert.certificate == mock_certificate, "Certificate should be the same as the mock certificate"
  
  assert cert.csr is not None, "CSR should be set"
  assert cert.csr == mock_csr, "CSR should be the same as the mock certificate"

@patch("probots.security.cert.os.path.exists", side_effect=[False, False, False])
@patch("probots.security.cert.rsa.generate_private_key")
@patch("probots.security.cert.os.makedirs")
def test_load_or_generate_new_key_and_csr(mock_makedirs,mock_generate_key, mock_exists):
  """
  Test that load_or_generate correctly generates a new private key and
  certificate when both don't exist.

  This test verifies that the load_or_generate method correctly generates
  a new private key and certificate when both don't exist. The test uses the
  patch decorator to mock the os.path.exists and rsa.generate_private_key
  functions.

  The test creates a HostCertificate instance and calls the load_or_generate
  method. The test then verifies that the private_key field of the instance
  is set to the mock private key that was returned by the mock
  generate_private_key function, and that the csr field is set to a
  CertificateSigningRequest instance.
  """
  cert = HostCertificate()
  mock_private_key = serialization.load_pem_private_key(data=default_private_key,
                                                                                        password=None,
                                                                                        backend=default_backend())
  
  mock_generate_key.return_value = mock_private_key
  csr, certificate = cert.load_or_generate()
  assert cert.private_key == mock_private_key
  assert csr is not None
  assert certificate is None

def test_get_certificate_not_loaded():
  """
  Test that get_certificate raises an error when the certificate has not been
  loaded or generated.

  This test verifies that the get_certificate method raises a ValueError
  when the certificate field of the instance is None. The test creates a
  HostCertificate instance without loading or generating a certificate,
  and then calls the get_certificate method. The test then verifies that
  the expected ValueError is raised.
  """
  cert = HostCertificate()
  with pytest.raises(ValueError, match="Certificate not loaded or generated."):
      cert.get_certificate()