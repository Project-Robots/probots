import os
import pytest
import datetime
import pytz
from unittest import mock
from pydantic import ValidationError
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from probots.security.store import get_default_paths, CertificateStore  # Replace with actual module name

@pytest.fixture
def mock_os():
    with mock.patch("os.makedirs") as makedirs, \
         mock.patch("os.geteuid", return_value=1000), \
         mock.patch("os.path.exists", return_value=True):
        yield {"makedirs": makedirs}

@pytest.fixture
def mock_load_certificates():
    with mock.patch("probots.security.store.CertificateStore.load_certificates") as load_certificates:
        load_certificates.return_value = []
        yield load_certificates
        
@pytest.fixture
def valid_certificate():
    cert_pem = b"""-----BEGIN CERTIFICATE-----
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

    cert = x509.load_pem_x509_certificate(cert_pem, default_backend())
    return cert

@pytest.fixture
def expired_certificate():
    cert_pem = b"""-----BEGIN CERTIFICATE-----
MIIEjDCCA3SgAwIBAgISA2sA9YVjquwaVo/yEyeUp8Y6MA0GCSqGSIb3DQEBCwUA
MDIxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MQswCQYDVQQD
EwJSMzAeFw0yNDA1MDgwNjA0NDVaFw0yNDA4MDYwNjA0NDRaMC4xLDAqBgNVBAMT
I3NlY3VyaXR5LWd1YXJkLmpsbWlsbGVyZWxlY3RyaWMuY29tMFkwEwYHKoZIzj0C
AQYIKoZIzj0DAQcDQgAEAO63g/YTdx/u3RvqgK+f2k4Ls+PFfQaVqIQDPd+xfjDC
4u6vCj+Aj1BSv/vdaRiMUzFeBQ+7b2uc5bMUUeWBsaOCAmkwggJlMA4GA1UdDwEB
/wQEAwIHgDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwDAYDVR0TAQH/
BAIwADAdBgNVHQ4EFgQU5aXMLXVBeNgOmeSrYxckju3AU4UwHwYDVR0jBBgwFoAU
FC6zF7dYVsuuUAlA5h+vnYsUwsYwVQYIKwYBBQUHAQEESTBHMCEGCCsGAQUFBzAB
hhVodHRwOi8vcjMuby5sZW5jci5vcmcwIgYIKwYBBQUHMAKGFmh0dHA6Ly9yMy5p
LmxlbmNyLm9yZy8wcgYDVR0RBGswaYIibGlnaHRidWxiLWRldi5qbG1pbGxlcmVs
ZWN0cmljLmNvbYIebGlnaHRidWxiLmpsbWlsbGVyZWxlY3RyaWMuY29tgiNzZWN1
cml0eS1ndWFyZC5qbG1pbGxlcmVsZWN0cmljLmNvbTATBgNVHSAEDDAKMAgGBmeB
DAECATCCAQQGCisGAQQB1nkCBAIEgfUEgfIA8AB3AD8XS0/XIkdYlB1lHIS+DRLt
kDd/H4Vq68G/KIXs+GRuAAABj1cE1OgAAAQDAEgwRgIhAPfzof23COUJ3vdLM+MX
OJVk/lOKDjMntgGkdlxZhXwBAiEAmy7Rqg4fikdB4hEDXlcUIUXAHlT02Q2vH1je
e2kQzPcAdQAZmBBxCfDWUi4wgNKeP2S7g24ozPkPUo7u385KPxa0ygAAAY9XBNUC
AAAEAwBGMEQCIAgta8PRpu9FG7nxmngbuUJx1ddTM6mIaExY6CCxe8t8AiBaoKF2
bfEVSbVnTuvY4AwMRn8PAAqGIZpATYhzy95LNDANBgkqhkiG9w0BAQsFAAOCAQEA
JFJSknXjGy/H+POVzFZl6bHIDthwHfQw43cvZeIo0FY2Lq4qGib+lOvVsn9BmN4A
1TVyHplp5p2sO5iRcLe1kEoP6Ao/DDP0HmSyrqa/Dd37NTa/kS/iLVnQh5Lqmlrv
6JCsrbIHUTBQ/rgRt6yk+Xk2tos3TPlvhojQbGPs66rNGJJjYPzFa/oY4tAPDSpc
Z62Unqc0owULm4ajT4BG32i/aShrt2meGTaTZe1mHzd3K/Hkcmq1oC/H+0t6wdWm
94svvnst8N2aNJCbe22/PC+TKZvyxR6+pj4fd7PayiqbslHtiX/n7Bcm25c42+fG
8zG+DY3kBpRcUBlek5l4KQ==
-----END CERTIFICATE-----"""

    cert = x509.load_pem_x509_certificate(cert_pem, default_backend())
    return cert

def test_get_default_paths_root():
    with mock.patch("os.geteuid", return_value=0):
        paths = get_default_paths("test_robot")
        assert paths["store_path"] == "/etc/test_robot/store/test_robot.store"

def test_get_default_paths_non_root():
    with mock.patch("os.geteuid", return_value=1000):
        paths = get_default_paths("test_robot")
        assert paths["store_path"] == os.path.expanduser("~/.test_robot/store/test_robot.store")

def test_certificate_store_init(mock_os, mock_load_certificates):
    store = CertificateStore(robot_name="test_robot")
    assert store.robot_name == "test_robot"
    assert "store_path" in store.__fields__
    mock_os["makedirs"].assert_called_once()
    mock_load_certificates.assert_called_once()

def test_add_certificate_valid(mock_os, valid_certificate):
    store = CertificateStore(robot_name="test_robot")
    with mock.patch("builtins.open", mock.mock_open()) as mock_file:
        result = store.add_certificate(valid_certificate)
        assert result is True
        mock_file().write.assert_called_once()

def test_add_certificate_invalid(mock_os, expired_certificate):
    store = CertificateStore(robot_name="test_robot")
    with pytest.raises(ValueError, match="Certificate is not valid or has expired"):
        store.add_certificate(expired_certificate)

def test_add_certificate_duplicate(mock_os, valid_certificate):
    store = CertificateStore(robot_name="test_robot")
    with mock.patch("builtins.open", mock.mock_open()):
        store.certificates = {valid_certificate.subject: valid_certificate}
        with pytest.raises(ValueError, match="Certificate is already in the store"):
            store.add_certificate(valid_certificate)

def test_load_certificates_no_files(mock_os):
    with mock.patch("os.listdir", return_value=[]):
        store = CertificateStore(robot_name="test_robot")
        certificates = store.load_certificates()
        assert certificates == {}

def test_load_certificates_with_valid_and_expired(mock_os, valid_certificate, expired_certificate):
    store = CertificateStore(robot_name="test_robot")
    with mock.patch("os.listdir", return_value=["valid_cert.pem", "expired_cert.pem"]), \
         mock.patch("builtins.open", mock.mock_open(read_data=valid_certificate.public_bytes(serialization.Encoding.PEM))):
        
        certs = store.load_certificates()
        assert len(certs) == 1
        assert valid_certificate.subject in certs

# def test_certificate_store_validation_error():
#     with pytest.raises(ValidationError):
#         CertificateStore(robot_name=123)  # Invalid robot_name type

def test_certificate_store_missing_store_path():
    store = CertificateStore(robot_name="test_robot")
    assert store.store_path
