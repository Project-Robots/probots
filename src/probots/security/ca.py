""" A module for working with certificate authorities. """

from ast import Name
import os
from datetime import datetime, timedelta

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from pytz import utc

from probots import security


class RootCertificateAuthority:
    """Root certificate authority class."""

    key: rsa.RSAPrivateKey
    crt: x509.Certificate
    key_file: str
    crt_file: str

    def __init__(self, key_file: str, crt_file: str):
        """
        Initializes a new instance of the CertificateAuthority class.

        Args:
          key_file: The file path to the private key.
          crt_file: The file path to the certificate.
        """
        self.key_file = key_file
        self.crt_file = crt_file

        self.load()

    def load(self):
        """
        Loads the private key and certificate from the specified files.
        """
        if os.path.exists(self.key_file):
            self.key = security.load_private_key(self.key_file)
            new_key = False
        else:
            self.key = rsa.generate_private_key(
                public_exponent=security.PUBLIC_EXPONENT,
                key_size=security.KEY_SIZE,
            )
            new_key = True

        if new_key is False and os.path.exists(self.crt_file):
            self.crt = security.load_certificate(self.crt_file)
        else:

            subject: Name = x509.Name(
                attributes=[
                    x509.NameAttribute(
                        oid=NameOID.COMMON_NAME,
                        value="Elvorath S.A.F.E Root Certificate Authority",
                    ),
                    x509.NameAttribute(
                        oid=NameOID.ORGANIZATION_NAME,
                        value="Elvorath",
                    ),
                    x509.NameAttribute(
                        oid=NameOID.ORGANIZATIONAL_UNIT_NAME,
                        value="Security and Forensics Engineering",
                    ),
                    x509.NameAttribute(
                        oid=NameOID.COUNTRY_NAME,
                        value="US",
                    ),
                    x509.NameAttribute(
                        oid=NameOID.STATE_OR_PROVINCE_NAME,
                        value="California",
                    ),
                    x509.NameAttribute(
                        oid=NameOID.LOCALITY_NAME,
                        value="Placentia",
                    ),
                    x509.NameAttribute(
                        oid=NameOID.POSTAL_CODE,
                        value="92870",
                    ),
                    x509.NameAttribute(
                        oid=NameOID.EMAIL_ADDRESS,
                        value="elvorath@thoughtparameters.com",
                    ),
                ]
            )

            issuer: Name = subject

            self.crt = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(issuer)
                .serial_number(x509.random_serial_number())
                .public_key(self.key.public_key())
                .not_valid_before(datetime.now(utc))
                .not_valid_after(datetime.now(utc) + timedelta(days=security.VALIDITY))
                .add_extension(
                    extval=x509.BasicConstraints(ca=True, path_length=None),
                    critical=True,
                )
                .add_extension(
                    extval=x509.KeyUsage(
                        digital_signature=True,
                        content_commitment=False,
                        key_encipherment=False,
                        data_encipherment=False,
                        key_agreement=False,
                        key_cert_sign=True,
                        crl_sign=True,
                        encipher_only=False,
                        decipher_only=False,
                    ),
                    critical=True,
                )
                .add_extension(
                    extval=x509.SubjectKeyIdentifier.from_public_key(
                        self.key.public_key()
                    ),
                    critical=False,
                )
                .sign(
                    private_key=self.key,
                    algorithm=hashes.SHA256(),
                    rsa_padding=security.RSA_PADDING,
                    backend=default_backend(),
                )
            )

    def save(self):
        """
        Save the private key and certificate to the specified files.
        """
        saved_private = False
        saved_certificate = False
        try:
            with open(self.key_file, "wb") as f:
                f.write(
                    security.private_key_to_pem(self.key),
                )
            saved_private = True
        except OSError as e:
            print(f"Error saving private key: {e}")

        try:
            with open(file=self.crt_file, mode="wb") as f:
                f.write(
                    self.crt.public_bytes(encoding=serialization.Encoding.PEM)
                )
            saved_certificate = True
        except OSError as e:
            print(f"Error saving certificate: {e}")

        return saved_private and saved_certificate


class IntermediateCertificateAuthority:
    """Intermediate Certificate Authority class."""

    key: rsa.RSAPrivateKey
    crt: x509.Certificate
    key_file: str
    crt_file: str
    rootca_key: rsa.RSAPrivateKey
    rootca_crt: x509.Certificate

    def __init__(
        self,
        key_file: str,
        crt_file: str,
        rootca_key: rsa.RSAPrivateKey,
        rootca_crt: x509.Certificate,
    ) -> None:
        """
        Initializes a new instance of the IntermediateCertificateAuthority class.
        """
        self.key_file = key_file
        self.crt_file = crt_file

        self.rootca_key = rootca_key
        self.rootca_crt = rootca_crt

        self.load()

    def load(self):
        """
        Loads the private key and certificate from the specified files.
        """
        if os.path.exists(self.key_file):
            self.key = security.load_private_key(self.key_file)
            new_key = False
        else:
            self.key = rsa.generate_private_key(
                public_exponent=security.PUBLIC_EXPONENT,
                key_size=security.KEY_SIZE,
            )
            new_key = True

        if new_key is False and os.path.exists(self.crt_file):
            self.crt = security.load_certificate(self.crt_file)
        else:
            subject = x509.Name(
                attributes=[
                    x509.NameAttribute(
                        oid=NameOID.COMMON_NAME,
                        value="Elvorath S.A.F.E Intermediate Certificate Authority",
                    ),
                    x509.NameAttribute(
                        oid=NameOID.ORGANIZATION_NAME,
                        value="Elvorath",
                    ),
                    x509.NameAttribute(
                        oid=NameOID.ORGANIZATIONAL_UNIT_NAME,
                        value="Security and Forensics Engineering",
                    ),
                    x509.NameAttribute(
                        oid=NameOID.COUNTRY_NAME,
                        value="US",
                    ),
                    x509.NameAttribute(
                        oid=NameOID.STATE_OR_PROVINCE_NAME,
                        value="California",
                    ),
                    x509.NameAttribute(
                        oid=NameOID.LOCALITY_NAME,
                        value="Placentia",
                    ),
                    x509.NameAttribute(
                        oid=NameOID.POSTAL_CODE,
                        value="92870",
                    ),
                    x509.NameAttribute(
                        oid=NameOID.EMAIL_ADDRESS,
                        value="elvorath@thoughtparameters.com",
                    ),
                ]
            )

            self.crt = (
                x509.CertificateBuilder()
                .subject_name(name=subject)
                .issuer_name(name=self.rootca_crt.subject)
                .serial_number(number=x509.random_serial_number())
                .public_key(key=self.key.public_key())
                .not_valid_before(time=datetime.now(utc))
                .not_valid_after(time=datetime.now(utc) + timedelta(security.VALIDITY))
                .add_extension(
                    extval=x509.BasicConstraints(ca=True, path_length=0),
                    critical=True,
                )
                .add_extension(
                    extval=x509.KeyUsage(
                        digital_signature=False,
                        content_commitment=False,
                        key_encipherment=False,
                        data_encipherment=False,
                        key_agreement=False,
                        key_cert_sign=True,
                        crl_sign=True,
                        encipher_only=False,
                        decipher_only=False,
                    ),
                    critical=True,
                )
                .add_extension(
                    extval=x509.SubjectKeyIdentifier.from_public_key(
                        public_key=self.key.public_key()
                    ),
                    critical=False,
                )
                .add_extension(
                    extval=x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                        ski=self.rootca_crt.extensions.get_extension_for_class(
                            x509.SubjectKeyIdentifier
                        ).value
                    ),
                    critical=False,
                )
                .sign(
                    private_key=self.rootca_key,
                    algorithm=hashes.SHA256(),
                    rsa_padding=security.RSA_PADDING,
                    backend=default_backend(),
                )
            )

    def save(self):
        """
        Save the private key and certificate to the specified files.
        """
        saved_private = False
        saved_certificate = False
        try:
            with open(self.key_file, "wb") as f:
                f.write(
                    security.private_key_to_pem(self.key),
                )
            saved_private = True

        except OSError as e:
            print(f"Error saving private key: {e}")

        try:
            with open(self.crt_file, "wb") as f:
                f.write(self.crt.public_bytes(encoding=serialization.Encoding.PEM))
            saved_certificate = True
        except OSError as e:
            print(f"Error saving certificate: {e}")

        return saved_private and saved_certificate

    def sign(self, csr: x509.CertificateSigningRequest) -> x509.Certificate:
        """
        Signs a certificate signing request using the Intermediate CA's private key.

        Args:
          csr: The certificate signing request to sign.

        Returns:
          The signed certificate.
        """
        if csr is None:
            return None

        cert = (
            x509.CertificateBuilder()
            .subject_name(csr.subject)
            .issuer_name(self.crt.subject)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(utc))
            .not_valid_after(datetime.now(utc) + timedelta(security.VALIDITY))
            .add_extension(
                extval=x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .add_extension(
                extval=x509.SubjectAlternativeName(
                    general_names=csr.extensions.get_extension_for_class(
                        extclass=x509.SubjectAlternativeName
                    ).value
                ),
                critical=False,
            )
            .add_extension(
                extval=x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=True,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                extval=x509.ExtendedKeyUsage(
                    usages=[
                        x509.ExtendedKeyUsageOID.SERVER_AUTH,
                        x509.ExtendedKeyUsageOID.CLIENT_AUTH,
                    ]
                ),
                critical=False,
            )
            .add_extension(
                extval=x509.SubjectKeyIdentifier.from_public_key(csr.public_key()),
                critical=False,
            )
            .add_extension(
                extval=x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                    ski=self.crt.extensions.get_extension_for_class(
                        extclass=x509.SubjectKeyIdentifier
                    ).value
                ),
                critical=False,
            )
            .sign(
                private_key=self.key,
                algorithm=hashes.SHA256(),
                rsa_padding=security.RSA_PADDING,
                backend=default_backend(),
            )
        )

        return cert
