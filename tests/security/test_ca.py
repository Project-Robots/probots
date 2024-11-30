""" Tests for the security module. """

from unittest.mock import mock_open, patch

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from probots.security.ca import (IntermediateCertificateAuthority,
                                 RootCertificateAuthority)

private_key = b"""-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAyQ/WjCT1E6zu0gPWKXMXUfAU2EVq8NIzyTD6jvR2UaQ5fp3S
2+Thj2MZw18qJuVDjkyLYzyN0mBgzetIGPT2gic3KTIUnBRgjE9RLIqI3p+drkRC
atq3w772l5YC0gxvYTTv4UOmEBuW9k31RLSRf0th4yunLVnCTsSDQj0hJUFgAz7S
vmskJZBVdxErBokqfMZ5UnYWJUkqY6J5fmE6E+UcEe8WAKOn9YEoRTLAc2PXaj1O
NNVVYoP6ldEe7XmEoqm59SCdOYQm+a4/Mf3ChSx+AaDMGHqjlWSlSYWkqOoqtyjZ
mUmDwAS+qAnCNEDdoNLmizUGbY6FjOihgUbBRQIDAQABAoIBAAvmHo3bsA9SiC2w
oW+BiqtEOI+WCB6pafwppGJqcEgjnm1yXKS71md8d21bB+0WW1mkCQm97yy4nHID
Txh/AsmwFXEgMB0OjaowFX870Z7PNm82RfH58K8qcYCGFbOlnb/UeK/Np5nDcDsy
YOYIg6XTab8eeb3S1o9/zL7STFBeg7iFzUf+nORYPtezHFw6vPIQRKJ0kYDvCTBi
oKOdDlZ2QdA12zsw0/oYBz1TV1YWxsKyfsvIQ/bMfePYUV85OI3980ENjVliYTQk
ytL0eeX4B+uUEwwMoiQ4ckbeb8MSleH21/+CFiHTIqDQs2pnB91jYScUgVM9Q5fP
5m3ZS18CgYEA6l5vNaEXHJ6V2VDigKKKNaywK1yK1QnpGMwxYwn8K8oD0aXqcNFa
naC12d0httw2WogSxBn+JhtmaxqiUto9j8zS3DhSQQx17GI/3Or423AMnuWf1bGu
pdYJEi9IWOL9RGx4mR9/DwhhJobS45QQcc5jXDDFYK1gWN631u0QW6MCgYEA255w
pUeUD8faKcdWGXzGNqpzQmUfsqsQuQSosfqzq7359VgB6O+FSrDvyPRJ49chBdhp
3yJDFiAs7VnWK9hzYdQOjtyIw60GIzD1dw15337ed830DN44hg6oI/Zieyn/tsPT
VgDMXF4NgJG7INJjsHjzLzx1oI2dXvAptn89vfcCgYEAnq0vGB0nu623ALodkD/7
2RlA8SqnqFMcaTieW1KAU9ljOobdsmJbuor7dDSeReLUPfkQ04pRotU8Q1l1+yhd
M8XWIVlUf0wDbvaaDGVd9ZvoP5Bx5cl12DuQSqqOjfeox7G0+N71NGVU+TOhBonR
lGvKo7k1eR4JNEIeL7qzL4cCgYEAnpUi7AXqoRaDryVUQ6U4j6K3BZt1rxMdSSxX
D+VitcHBa2q4PlYuXoezLd1QOahPHSRvFoNsA98J8f2rzA9JCbwRIxGV5A3dX63r
oaLmfP7kb4gVEPGpyQtuWEGCTUM/dd6jjPeYmZ4Ei/EvOX0SJQzBNTuoCF4Z48Lx
q+jnUXMCgYBJWFvoiy8J/r7tE4oEtuLmzQky1+kupUaQITaii1gEWDsBi+x0ua3A
2bD3Vsurgv0Xb4+GDpG0iyJnjTTsYY2lXfgDzGURuChjf9bzpqgaBAp0CnWoGef6
ZCEADQwiPIb6mxJbQO51hYHh1u+DMEZO5Ml5ry2Q5yOgcij2Bt8iLg==
-----END RSA PRIVATE KEY-----"""

intermediate_key = b"""-----BEGIN PRIVATE KEY-----
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

certificate = b"""-----BEGIN CERTIFICATE-----
MIID7DCCAp+gAwIBAgIUWwj4TlvmzjI5BwNr4HmQTnJTp0wwQgYJKoZIhvcNAQEK
MDWgDzANBglghkgBZQMEAgEFAKEcMBoGCSqGSIb3DQEBCDANBglghkgBZQMEAgEF
AKIEAgIA3jB7MQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTESMBAG
A1UEBwwJUGxhY2VudGlhMRcwFQYDVQQKDA5Qcm9qZWN0IFJvYm90czEUMBIGA1UE
CwwLRW5naW5lZXJpbmcxFDASBgNVBAMMC29yYml0LmxvY2FsMB4XDTI0MTExNjA5
MzQwMVoXDTM0MTExNDA5MzQwMVowezELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNh
bGlmb3JuaWExEjAQBgNVBAcMCVBsYWNlbnRpYTEXMBUGA1UECgwOUHJvamVjdCBS
b2JvdHMxFDASBgNVBAsMC0VuZ2luZWVyaW5nMRQwEgYDVQQDDAtvcmJpdC5sb2Nh
bDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMkP1owk9ROs7tID1ilz
F1HwFNhFavDSM8kw+o70dlGkOX6d0tvk4Y9jGcNfKiblQ45Mi2M8jdJgYM3rSBj0
9oInNykyFJwUYIxPUSyKiN6fna5EQmrat8O+9peWAtIMb2E07+FDphAblvZN9US0
kX9LYeMrpy1Zwk7Eg0I9ISVBYAM+0r5rJCWQVXcRKwaJKnzGeVJ2FiVJKmOieX5h
OhPlHBHvFgCjp/WBKEUywHNj12o9TjTVVWKD+pXRHu15hKKpufUgnTmEJvmuPzH9
woUsfgGgzBh6o5VkpUmFpKjqKrco2ZlJg8AEvqgJwjRA3aDS5os1Bm2OhYzooYFG
wUUCAwEAATBCBgkqhkiG9w0BAQowNaAPMA0GCWCGSAFlAwQCAQUAoRwwGgYJKoZI
hvcNAQEIMA0GCWCGSAFlAwQCAQUAogQCAgDeA4IBAQCxHBc1hVE+4gTshOnmePjG
AOfgzvka6/8QL1zN+TOwaZgipBvcBd7YWDkzG/Z8zksSHAl2YOSUBeVhHXTUosF1
cvBjJyuCxJxy2xbyaivj2VWDhUVc0s4Mr90L8wJGGjlqiAGfG2hxgd4VnWibNe+9
A67SSyB7rFX8uog9DqRzBrLyMXfhMugDIvYw3vqZf3Id6hSUcQnn7DuWHygc4TEP
9/Oi7v/0CXpjLhRvOWQurVJ3dRe9hiGlLDS8DvxqujWO7nun76lMjzv2Y035psUx
dIA44LGV8laPWlD6D1X7DeE4LVALaRmuhSHZYlPGzEWE2Q2xMEGv/4miU9OpWzED
-----END CERTIFICATE-----"""

intermediate_certificate = b"""-----BEGIN CERTIFICATE-----
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


def test_root_ca_load_success():
    """
    Test that the RootCertificateAuthority can successfully load both
    the private key and certificate from the specified files.
    """
    with patch("os.path.exists", return_value=True):
        with patch(
            "probots.security.load_private_key",
            return_value=serialization.load_pem_private_key(
                data=private_key, password=None
            ),
        ):
            with patch(
                "probots.security.load_certificate",
                return_value=x509.load_pem_x509_certificate(data=certificate),
            ):

                ca = RootCertificateAuthority("mock_key.pem", "mock_crt.pem")
                assert ca.key is not None
                assert ca.crt is not None


def test_root_ca_load_failure_key():
    """
    Tests that the RootCertificateAuthority class can load a certificate
    successfully from the specified file, but fails to load a private key
    from the specified file, so it should generate a new private key.
    """
    with patch("os.path.exists", side_effect=[False, True]):
        ca = RootCertificateAuthority("mock_key.pem", "mock_crt.pem")
        assert ca.key is not None  # Should generate a new key
        assert ca.crt is not None


def test_root_ca_load_failure_crt():
    """
    Tests that the RootCertificateAuthority class can load a private key
    successfully from the specified file, but fails to load a certificate
    from the specified file, so it should generate a new certificate.
    """
    with patch("os.path.exists", side_effect=[True, False]):
        with patch(
            "probots.security.load_private_key",
            return_value=serialization.load_pem_private_key(
                data=private_key, password=None
            ),
        ):
            ca = RootCertificateAuthority("mock_key.pem", "mock_crt.pem")
            assert ca.crt is not None  # Should generate a new certificate


def test_root_ca_save_success():
    """
    Tests that the RootCertificateAuthority class can save the private
    key and certificate to the specified files successfully.
    """
    ca = RootCertificateAuthority("mock_key.pem", "mock_crt.pem")
    ca.key = serialization.load_pem_private_key(data=private_key, password=None)
    ca.crt = x509.load_pem_x509_certificate(data=certificate)

    with patch("builtins.open", mock_open()) as mock_file:
        assert ca.save() is True
        mock_file.assert_called()


def test_intermediate_ca_load_success():
    """
    Tests that the IntermediateCertificateAuthority class can load the
    private key and certificate from the specified files successfully.
    """
    root_ca = RootCertificateAuthority("mock_root_key.pem", "mock_root_crt.pem")
    root_ca.key = serialization.load_pem_private_key(data=private_key, password=None)
    root_ca.crt = x509.load_pem_x509_certificate(certificate)

    with patch("os.path.exists", return_value=True):
        with patch(
            "probots.security.load_private_key",
            return_value=serialization.load_pem_private_key(
                data=private_key, password=None
            ),
        ):
            with patch(
                "probots.security.load_certificate",
                return_value=x509.load_pem_x509_certificate(data=certificate),
            ):
                ca = IntermediateCertificateAuthority(
                    "mock_key.pem", "mock_crt.pem", root_ca.key, root_ca.crt
                )
                assert ca.key is not None
                assert ca.crt is not None


def test_intermediate_ca_save_success():
    """
    Tests that the IntermediateCertificateAuthority class can save the
    private key and certificate to the specified files successfully.
    """
    root_ca = RootCertificateAuthority("mock_root_key.pem", "mock_root_crt.pem")
    ca = IntermediateCertificateAuthority(
        "mock_key.pem", "mock_crt.pem", root_ca.key, root_ca.crt
    )

    with patch("builtins.open", mock_open()) as mock_file:
        assert ca.save() is True
        assert mock_file.call_count == 2
