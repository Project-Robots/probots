""" Tests for the security module. """

from unittest.mock import patch, mock_open
from probots.security import load_private_key, load_certificate, load_csr

private_key = b"""-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCUUy5Tw6aRVzBr
GlwCUNOrpW+aAeFtVYyBYSvzDWpFiz/eXivk8GoDto0c8ugtGE8l6tvivQN97kR4
UzGdNjc1fkGHbA79rJTmOofTKc5c2mUMet+Lp4fBzaoJ/0dzazHpapUHIg2quPZB
oF35Pb/CehMNdouWCeRKpADQrDRdPFB5SqbSQcfynaVKtt2CEOrpDSUqutZgS9rP
FiGvvIge1igvbJmVQbJpSmgLJrpYTWdBD7xMLvvstW93mDQ7DtKKe7rA4MdmCfCK
TyLikf4i1UAeuB5rQD+0QZ4d1erR4T/rXH8TVYnbOQuXviQS9Bxwa4ow0dY6IMvw
zbV4bKmZAgMBAAECggEAPErTuhj9zHa0p9S/MfHJGSzWgLPi/p6Xzr/BLbt2R26j
N7DwBs/zSC8cjXfwCOSox7EAUNqkYLxJ+N9Ye59eMdBwsquqLFPK8ws3yw5jZDsi
eEA6PnqLJKyFQisS0Efysf8xNQUSqSMmdubJTFdda6BTvlVByGuc8PpZmnllj8Am
KyYYI4R7KGUiLZ2R/zeaq71SpDfe/Yh9R61pGu7uul6cBAA0kvlBZx3abJS+i6AH
w3HBGUx2rUXeKyucRaDdlAFZhn/WQfsbIU2aOcphmtE7pQ8P0Y/JZpdYr4Y30qUs
077nQpKgaQJg00XrCQPtugSV/ETEKl6dDOaxMvTTQQKBgQDKrXEx12RBt20qxt7l
KBo+FOJEzfxpe6cIbkpYlR7oGv7ya1wfoKeVvswEQXaS3xfmzYOoKDvwl/AHGVva
uVo85q9mhuH2M34wbowfX2Hd4prWxnYbQqvyTuka8WEA/mAF1+E3Rs6dSiDGwszg
xKqOIFs4xCNTG5LY82ratPXc/wKBgQC7WQgDQ3g2neV/t1qCwrs7LDEKyJP1X+Hp
cIeqReWkickoNeDiUt+4ajtWnlZoqVj8f0t1XD8nEScVyth97zShbpwS9aOEw60k
i02WvM0nHq69sfJ5ivxJzFqEpSn29r5FrPgF0wsfp6t4cFKa9KiqKXMHJzxE2327
1dXhb5xBZwKBgQC3q6w8DcT2ZQLSVDzkkI4Pmp9e2QkYko1Rb5mCY0kJ8IUALVjj
9JRKeQisBqMtAG3JpI7eUe/X3ekQleOO+JAVRrzHfg7CLfH6dAQZ3jdzfArz/hBE
Lgxi3y4SU5Kj8uIUCYo4rLtLAUVoulouiytA94OTkvOsOf2/DADWyE1TAwKBgGhy
XVY8cjO42a7XUN2fpPR7UagaZOqilvcnJmtWZo3Rx1TknMhwvYs5pnVG9xOIfjTe
3vnCAO9Nz8WFfibPij8JxHeJfK1Szh+Wjh4gihtqLq9RGsaKJtcZ18klr3yg2TlN
EkVlAEmYl68gp9z9015yl0+An0ggOjvTHld9eta3AoGAQ5d3WvQ6XyGL4ugLs9uS
/4BOP/oJd/OgvqwYVRNy6ha3m4qxFnPLv1Zhy2eKetWPr3uS3pkZ2DNv+2Id2mRg
xc2MrxXAOZehxE24tQ0EtXHtIdYtcQFQvClb18lkc/v80w5Inx40IRBkfUJgNNuk
xHOI+6jPoGxgRJ2WTMb/8+8=
-----END PRIVATE KEY-----"""

certificate = b"""-----BEGIN CERTIFICATE-----
MIIELzCCAxegAwIBAgIUXDCZ+HZmOo1kYyGOUXT4SurptrAwDQYJKoZIhvcNAQEL
BQAwgb8xCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRIwEAYDVQQH
DAlQbGFjZW50aWExHzAdBgNVBAoMFlRob3VnaHQgUGFyYW1ldGVycyBMTEMxFDAS
BgNVBAsMC0VuZ2luZWVyaW5nMSQwIgYDVQQDDBtvcmJpdC50aG91Z2h0cGFyYW1l
dGVycy5jb20xKjAoBgkqhkiG9w0BCQEWG29yYml0QHRob3VnaHRwYXJhbWV0ZXJz
LmNvbTAeFw0yNDExMjYxODI5MTRaFw0zMjAyMjgxODI5MTRaMIG/MQswCQYDVQQG
EwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTESMBAGA1UEBwwJUGxhY2VudGlhMR8w
HQYDVQQKDBZUaG91Z2h0IFBhcmFtZXRlcnMgTExDMRQwEgYDVQQLDAtFbmdpbmVl
cmluZzEkMCIGA1UEAwwbb3JiaXQudGhvdWdodHBhcmFtZXRlcnMuY29tMSowKAYJ
KoZIhvcNAQkBFhtvcmJpdEB0aG91Z2h0cGFyYW1ldGVycy5jb20wggEiMA0GCSqG
SIb3DQEBAQUAA4IBDwAwggEKAoIBAQCUUy5Tw6aRVzBrGlwCUNOrpW+aAeFtVYyB
YSvzDWpFiz/eXivk8GoDto0c8ugtGE8l6tvivQN97kR4UzGdNjc1fkGHbA79rJTm
OofTKc5c2mUMet+Lp4fBzaoJ/0dzazHpapUHIg2quPZBoF35Pb/CehMNdouWCeRK
pADQrDRdPFB5SqbSQcfynaVKtt2CEOrpDSUqutZgS9rPFiGvvIge1igvbJmVQbJp
SmgLJrpYTWdBD7xMLvvstW93mDQ7DtKKe7rA4MdmCfCKTyLikf4i1UAeuB5rQD+0
QZ4d1erR4T/rXH8TVYnbOQuXviQS9Bxwa4ow0dY6IMvwzbV4bKmZAgMBAAGjITAf
MB0GA1UdDgQWBBSBN67SB7nhE70QKzdVRu82kw+lXTANBgkqhkiG9w0BAQsFAAOC
AQEAZVlx15mBf9RVS1bjU5+Yi05EnhLNrEQKmW4qvh5RZqEGxN5XIm5rLnAiCnrx
L5/tNIX5ZaK999IokguqS07KfyxUJvxII3L102lMjlhABg0sYhPQ8QwY+sjn+tnO
gzVn/ujULFmTXW8IwJjJvvZPEbYYNhg1Vwxexeh8BGArJZe1QU0rMusjKxMvuRXC
73BVXv14sRsHoNWzKxxIwvlVsQ4Wpt+hrdkf3P1EZM6NT7b6anrKlmPNgVSJOfxa
2Kyz8BkB3+tr6bBJdacpAk7LhxYy5gq9x6Px/HcypEXSXdmbMJ03xaB7++jewiVN
IaXe6wEhLvK3UUn7VyC2l0dxOQ==
-----END CERTIFICATE-----"""

csr = b"""-----BEGIN CERTIFICATE REQUEST-----
MIIDBTCCAe0CAQAwgb8xCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlh
MRIwEAYDVQQHDAlQbGFjZW50aWExHzAdBgNVBAoMFlRob3VnaHQgUGFyYW1ldGVy
cyBMTEMxFDASBgNVBAsMC0VuZ2luZWVyaW5nMSQwIgYDVQQDDBtvcmJpdC50aG91
Z2h0cGFyYW1ldGVycy5jb20xKjAoBgkqhkiG9w0BCQEWG29yYml0QHRob3VnaHRw
YXJhbWV0ZXJzLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJRT
LlPDppFXMGsaXAJQ06ulb5oB4W1VjIFhK/MNakWLP95eK+TwagO2jRzy6C0YTyXq
2+K9A33uRHhTMZ02NzV+QYdsDv2slOY6h9MpzlzaZQx634unh8HNqgn/R3NrMelq
lQciDaq49kGgXfk9v8J6Ew12i5YJ5EqkANCsNF08UHlKptJBx/KdpUq23YIQ6ukN
JSq61mBL2s8WIa+8iB7WKC9smZVBsmlKaAsmulhNZ0EPvEwu++y1b3eYNDsO0op7
usDgx2YJ8IpPIuKR/iLVQB64HmtAP7RBnh3V6tHhP+tcfxNVids5C5e+JBL0HHBr
ijDR1jogy/DNtXhsqZkCAwEAAaAAMA0GCSqGSIb3DQEBCwUAA4IBAQAc1upcvXyD
yqu/BPySAziRm+jnMcIGfX06bccz6Y1jNRqp5cdBhQshNlsRVRAiTsHU1qvaKU8z
ojS0cuG21uJNt5pnoC75kRu4FVa8IoWIwNHLmhA8PYnSrk5/tXerTfHsM1J4q/V/
ciubbB+mp7uWszuMD/IuAlSImM23bXysc3g5Vzwd1WdFOQ2etfl3COyzmlbsj7o5
ap/immKyWcLMlmjdspueeMIrKjJ+YGC5OSsmnT5oqIZ8HoRMmBBKiH4VKNgi9UM+
EG6/dsT/LsApJzA9oFPHFocvAd74Z5iT3RYon8i+QCQOaz/kLGKTCNdTDjxikvfA
HsE8pjHUaBQF
-----END CERTIFICATE REQUEST-----"""


def test_load_private_key_success():
    """
    Test that loading a private key file returns a valid key.
    """
    with patch("os.path.exists", return_value=True):
        with patch("builtins.open", mock_open(read_data=private_key)):
            key = load_private_key("mock_private_key.pem")
            assert key is not None, "Key is None"
            # assert isinstance(key, rsa.RSAPrivateKey), "Key is not an instance of RSAPrivateKey"


def test_load_private_key_failure():
    """
    Test that loading a non-existent private key file returns None.
    """
    with patch("os.path.exists", return_value=False):
        with patch("builtins.open", side_effect=FileNotFoundError):
            key = load_private_key("non_existent_key.pem")
            assert key is None


def test_load_certificate_success():
    """
    Test that loading a certificate file returns a valid certificate.
    """
    with patch("os.path.exists", return_value=True):
        with patch("builtins.open", mock_open(read_data=certificate)):
            cert = load_certificate("mock_certificate.pem")
            assert cert is not None


def test_load_certificate_failure():
    """
    Test that loading a non-existent certificate file returns None.
    """
    with patch("builtins.open", side_effect=FileNotFoundError):
        cert = load_certificate("non_existent_cert.pem")
        assert cert is None


def test_load_csr_success():
    """
    Test that loading a certificate signing request file returns the CSR.
    """
    with patch("os.path.exists", return_value=True):
        with patch("builtins.open", mock_open(read_data=csr)):
            mock_csr = load_csr("mock_csr.pem")
            assert mock_csr is not None


def test_load_csr_failure():
    """
    Test that loading a non-existent certificate signing request file returns None.
    """
    with patch("os.path.exists", return_value=False):
        mock_csr = load_csr("non_existent_csr.pem")
        assert mock_csr is None
