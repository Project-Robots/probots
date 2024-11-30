""" Tests for the security module. """

from unittest.mock import MagicMock, patch

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from probots.security.certificate import NodeCertificate

node_key = serialization.load_pem_private_key(
    data=b"""-----BEGIN PRIVATE KEY-----
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
-----END PRIVATE KEY-----""",
    password=None,
)

node_csr = x509.load_pem_x509_csr(
    data=b"""-----BEGIN CERTIFICATE REQUEST-----
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
)

node_cert = x509.load_pem_x509_certificate(
    data=b"""-----BEGIN CERTIFICATE-----
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
)


class TestNodeCertificate:

    @patch("probots.security.load_private_key")
    @patch("probots.security.load_certificate")
    @patch("probots.security.load_csr")
    @patch("probots.security.rsa.generate_private_key")
    def test_init_with_existing_key_and_csr(
        self,
        mock_generate_key,
        mock_load_csr,
        mock_load_certificate,
        mock_load_private_key,
    ):
        mock_load_private_key.return_value = node_key
        mock_load_certificate.return_value = node_cert
        mock_load_csr.return_value = node_csr

        cert = NodeCertificate("private_key.pem", "certificate.pem", "csr.pem")

        assert cert.key is not None
        assert cert.cert is not None
        assert cert.csr is not None

    def test_init_generates_new_key_and_csr(self):
        cert = NodeCertificate("private_key.pem", "certificate.pem", "csr.pem")

        assert cert.key is not None
        assert cert.csr is not None
        assert cert.cert is None

    @patch("builtins.open", new_callable=MagicMock)
    def test_save_private_key(self, mock_open):
        cert = NodeCertificate("private_key.pem", "certificate.pem", "csr.pem")
        cert.save(save_key=True)

        assert mock_open.call_count == 1

    @patch("builtins.open", new_callable=MagicMock)
    def test_save_csr(self, mock_open):
        cert = NodeCertificate("private_key.pem", "certificate.pem", "csr.pem")
        cert.save(save_csr=True)

        assert mock_open.call_count == 1

    @patch("builtins.open", new_callable=MagicMock)
    def test_save_certificate(self, mock_open):
        cert = NodeCertificate("private_key.pem", "certificate.pem", "csr.pem")
        cert.cert = node_cert
        cert.save(save_cert=True)

        assert mock_open.call_count == 1

    def test_get_certificate(self):
        cert = NodeCertificate("private_key.pem", "certificate.pem", "csr.pem")
        cert.cert = node_cert
        assert cert.get_certificate() is cert.cert

    def test_set_certificate(self):
        cert = NodeCertificate("private_key.pem", "certificate.pem", "csr.pem")
        cert.set_certificate(node_cert)
        assert cert.cert is node_cert

    def test_get_csr(self):
        cert = NodeCertificate("private_key.pem", "certificate.pem", "csr.pem")
        assert cert.get_csr() is cert.csr
