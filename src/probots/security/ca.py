""" This module provides a Certificate Authority (CA) class for generating and verifying certificates. """
import os
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from datetime import datetime, timedelta
from pydantic import BaseModel, Field
import pytz # Import pytz for timezone handling

def get_default_ca_paths(robot_name="robot"):
    """Determine default paths based on the user privilege level."""
    if os.geteuid() == 0:  # Check if the user is root
        base_path = f"/etc/{robot_name}/ca"
    else:
        base_path = os.path.expanduser(f"~/.{robot_name}/ca")
    
    return {
        "private_key_path": os.path.join(base_path, "private_key.pem"),
        "certificate_path": os.path.join(base_path, "cacert.pem")
    }
    
class CertificateAuthority(BaseModel):
  country: str = Field(default="US", description="Country Name (2 letter code)")
  state: str = Field(default="California", description="State or Province Name (full name)")
  locality: str = Field(default="Placentia", description="Locality Name (eg, city)")
  organization: str = Field(default="Project Robots | Thought Parameters LLC", description="Organization Name (eg, company)")
  organizational_unit: str = Field(default="Engineering", description="Organizational Unit (eg, section)")
  common_name: str = Field(default="orbit.local", description="Common Name (e.g., server FQDN or YOUR name)")
  alt_names: list[str] = Field(default_factory=lambda: ["localhost", "orbit.local"], description="Subject Alternative Names")
  
  private_key_path: str = Field(default=None, description="Path to the CA private key")
  certificate_path: str = Field(default=None, description="Path to the CA certificate")
  robot_name: str = Field(default="robot", description="Name of the robot or application")
  private_key: str = Field(default=None, description="CA private key")
  certificate: str = Field(default=None, description="CA certificate")

  def __init__(self, **data):
    """
    Initialize the CertificateAuthority instance.

    If the private_key_path or certificate_path fields are not provided, they are
    set to default values based on the robot_name field.

    The _load_or_generate_ca method is called after the above initialization to
    load or generate the CA private key and certificate, as appropriate.
    """
    super().__init__(**data)
    paths = get_default_ca_paths(self.robot_name)
    self.private_key_path = self.private_key_path or paths["private_key_path"]
    self.certificate_path = self.certificate_path or paths["certificate_path"]
    
    self._load_or_generate_ca()
    
  def _load_or_generate_ca(self):
    """
    Load or generate the Certificate Authority (CA) private key and certificate.

    This method first ensures that the directory for the CA private key exists.
    If both the CA private key and certificate already exist at their specified paths,
    they are loaded into the instance. If either the private key or certificate does not
    exist, a new CA key and certificate are generated.

    The CA private key is loaded from the private key path, and the CA certificate
    is loaded from the certificate path. If loading fails, new ones are generated
    by invoking the `_generate_ca` method.
    """
    os.makedirs(os.path.dirname(self.private_key_path), exist_ok=True)

    if os.path.exists(self.private_key_path) and os.path.exists(self.certificate_path):
      # Load the CA private key
      with open(self.private_key_path, "rb") as key_file:
          self.private_key = serialization.load_pem_private_key(
              key_file.read(),
              password=None,
              backend=default_backend()
          )

      # Load the CA certificate
      with open(self.certificate_path, "rb") as cert_file:
          self.certificate = x509.load_pem_x509_certificate(
              cert_file.read(),
              backend=default_backend()
          )
    else:
      # Generate a new CA key and certificate if they don’t exist
      self._generate_ca()
      
  def _generate_ca(self): 
    """
    Generate a new Certificate Authority (CA) private key and certificate if they don't exist.
    
    This method generates a new CA key and certificate if the private key and certificate
    files do not exist. The generated key is an RSA key with a modulus of 8192 bits, and
    the certificate is self-signed with a validity period of 10 years.
    
    The generated key and certificate are saved to the private key path and certificate
    path specified in the constructor, respectively.
    """
    self.private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    subject = issuer = x509.Name([
      x509.NameAttribute(x509.NameOID.COUNTRY_NAME, self.country),
      x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME, self.state),
      x509.NameAttribute(x509.NameOID.LOCALITY_NAME, self.locality),
      x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, self.organization),
      x509.NameAttribute(x509.NameOID.ORGANIZATIONAL_UNIT_NAME, self.organizational_unit),
      x509.NameAttribute(x509.NameOID.COMMON_NAME, self.common_name)
    ])
    
    self.certificate = (
      x509.CertificateBuilder()
      .subject_name(subject)
      .issuer_name(issuer)
      .public_key(self.private_key.public_key())
      .serial_number(x509.random_serial_number())
      .not_valid_before(datetime.now(pytz.UTC))
      .not_valid_after(datetime.now(pytz.UTC) + timedelta(days=3650))
      .sign(private_key=self.private_key, rsa_padding=padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), algorithm=hashes.SHA256(), backend=default_backend())
    )

    with open(self.private_key_path, "wb") as key_file:
      key_file.write(
        self.private_key.private_bytes(
          encoding=serialization.Encoding.PEM,
          format=serialization.PrivateFormat.TraditionalOpenSSL,
          encryption_algorithm=serialization.NoEncryption()
        )
      )

    with open(self.certificate_path, "wb") as cert_file:
      cert_file.write(self.certificate.public_bytes(serialization.Encoding.PEM))
          
  def sign_csr(self, csr: x509.CertificateSigningRequest) -> x509.Certificate:
    """
    Sign a Certificate Signing Request (CSR) with the Certificate Authority (CA)
    private key.

    The returned certificate is a signed version of the CSR, with the CA as the
    issuer. The certificate is valid for 365 days and is not a CA certificate.

    Args:
      csr (x509.CertificateSigningRequest): The CSR to sign.

    Returns:
      x509.Certificate: The signed certificate.
    """
    certificate = (
      x509.CertificateBuilder()
      .subject_name(csr.subject)
      .issuer_name(self.certificate.subject)
      .public_key(csr.public_key())
      .serial_number(x509.random_serial_number())
      .not_valid_before(datetime.now(pytz.UTC))
      .not_valid_after(datetime.now(pytz.UTC) + timedelta(days=365))
      .add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True
      ).sign(private_key=self.private_key, rsa_padding=padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), algorithm=hashes.SHA256(), backend=default_backend())
    )
    return certificate
  
  def get_ca_certificate(self) -> x509.Certificate:
    """
    Get the CA certificate.

    Returns:
        x509.Certificate: The CA certificate.
    """
    if not isinstance(self.certificate, x509.Certificate):
      raise ValueError("CA certificate not found")
    
    return self.certificate
  
  def verify_certificate(self, certificate: x509.Certificate) -> bool:
    """
    Verify a certificate using the public key in the certificate.

    Parameters:
        certificate (x509.Certificate): The certificate to verify.

    Returns:
        bool: True if the certificate is valid, False otherwise.
    """
    try:
      certificate.public_key().verify(
        certificate.signature,
        certificate.tbs_certificate_bytes,
        padding.PSS(
          mgf=padding.MGF1(hashes.SHA256()),
          salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
      )
      return True
    except InvalidSignature:
      return False
  
  def verify_csr(self, csr: x509.CertificateSigningRequest) -> bool:
    """
    Verify a certificate signing request using the public key in the request.

    Parameters:
        csr (x509.CertificateSigningRequest): The certificate signing request to verify.

    Returns:
        bool: True if the certificate signing request is valid, False otherwise.
    """    
    try:
      csr.public_key().verify(
        csr.signature,
        csr.tbs_certrequest_bytes,
        padding.PSS(
          mgf=padding.MGF1(
            hashes.SHA256()
          ),
          salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
      )
      return True
    except InvalidSignature:
      return False
    

        
      
  
  
    
