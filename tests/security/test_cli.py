import pytest
from click.testing import CliRunner
from unittest.mock import patch, MagicMock
from cryptography import x509
import probots.security.cli as cert_cli
import os

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

default_csr = b"""-----BEGIN CERTIFICATE REQUEST-----
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
def runner():
    return CliRunner()

@patch("probots.security.cli.CertificateAuthority")
def test_init_ca(mock_ca, runner):
    """Test the init_ca command to initialize the Certificate Authority."""
    result = runner.invoke(cert_cli.init_ca, [])
    assert result.exit_code == 0
    mock_ca.return_value._generate_ca.assert_called_once()
    assert "Certificate Authority initialized successfully." in result.output

@patch("probots.security.cli.CertificateAuthority")
@patch("builtins.open", new_callable=MagicMock)
def test_sign_csr(mock_open, mock_ca, runner):
    """Test the sign_csr command to sign a CSR."""
    mock_open.return_value.__enter__.return_value.read.return_value = default_csr
    mock_ca.return_value.sign_csr.return_value.public_bytes.return_value = default_certificate
    
    result = runner.invoke(cert_cli.sign_csr, ['--csr-path', 'csr.pem', '--output', 'signed_cert.pem'])
    assert result.exit_code == 0
    mock_ca.return_value.sign_csr.assert_called_once()
    assert "CSR signed and saved to signed_cert.pem" in result.output

@patch("probots.security.cli.CertificateAuthority")
@patch("builtins.open", new_callable=MagicMock)
def test_verify_cert(mock_open, mock_ca, runner):
    """Test the verify_cert command to verify a certificate."""
    mock_open.return_value.__enter__.return_value.read.return_value = default_certificate
    mock_ca.return_value.verify_certificate.return_value = True
    
    result = runner.invoke(cert_cli.verify_cert, ['--cert-path', 'cert.pem'])
    assert result.exit_code == 0
    mock_ca.return_value.verify_certificate.assert_called_once()
    assert "Certificate verification result: Valid" in result.output

@patch("probots.security.cli.HostCertificate")
@patch("builtins.open", new_callable=MagicMock)
def test_generate_host_cert(mock_open, mock_host_cert, runner):
    """Test the generate_host_cert command to generate a host certificate and CSR."""
    mock_host_cert.return_value.load_or_generate.return_value = (MagicMock(public_bytes=MagicMock(return_value=b"mock_csr")), None)
    mock_host_cert.return_value.private_key.private_bytes.return_value = b"mock_private_key"
    
    result = runner.invoke(cert_cli.generate_host_cert, ['--host-name', 'testhost', '--output-dir', '.'])
    assert result.exit_code == 0
    assert "Generated CSR at ./testhost_csr.pem and key at ./testhost_key.pem" in result.output

@patch("probots.security.cli.CertificateStore")
@patch("builtins.open", new_callable=MagicMock)
def test_add_cert_to_store(mock_open, mock_store, runner):
    """Test the add_cert_to_store command to add a certificate to the store."""
    mock_open.return_value.__enter__.return_value.read.return_value = default_certificate
    
    result = runner.invoke(cert_cli.add_cert_to_store, ['--cert-path', 'cert.pem'])
    assert result.exit_code == 0
    mock_store.return_value.add_certificate.assert_called_once()
    assert "Certificate added to store" in result.output

@patch("probots.security.cli.CertificateStore")
def test_list_certificates(mock_store, runner):
    """Test the list_certificates command to list certificates in the store."""
    mock_cert = x509.load_pem_x509_certificate(data=default_certificate)
    mock_store.return_value.load_certificates.return_value = {mock_cert.subject: mock_cert}
    
    result = runner.invoke(cert_cli.list_certificates, [])
    assert result.exit_code == 0
    assert "Certificates in the store:" in result.output
    assert "CN=test_hostname,OU=Engineering,O=Thought Parameters LLC,L=Placentia,ST=California,C=US (Valid from 2024-11-12 21:07:30+00:00 to 2025-11-12 21:07:30+00:00)" in result.output

@patch("probots.security.cli.CertificateStore")
def test_list_certificates_empty(mock_store, runner):
    """Test the list_certificates command with no certificates in the store."""
    mock_store.return_value.load_certificates.return_value = {}
    
    result = runner.invoke(cert_cli.list_certificates, [])
    assert result.exit_code == 0
    assert "No certificates found in the store." in result.output
