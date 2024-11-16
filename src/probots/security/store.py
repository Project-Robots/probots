import os
from pydantic.v1 import BaseModel, Field
import datetime
import pytz

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

def get_default_paths(robot_name="robot"):
  """Determine default paths based on the user privilege level."""
  if os.geteuid() == 0:  # Check if the user is root
      base_path = f"/etc/{robot_name}/store/"
  else:
      base_path = os.path.expanduser(f"~/.{robot_name}/store/")

  return {
      "store_path": os.path.join(base_path, f"{robot_name}.store")
  }
  
class CertificateStore(BaseModel):
  store_path: str = Field(default=None, description="Path to the certificate store")
  robot_name: str = Field(default="robot", description="Name of the robot or application")
  certificates: dict = Field(default_factory=dict, description="Dictionary of certificates")
  
  def __init__(self, robot_name="robot"):
    super().__init__()
    
    self.robot_name = robot_name
    self.store_path = get_default_paths(robot_name)["store_path"]
    # Create the store directory if it doesn't exist
    os.makedirs(self.store_path, exist_ok=True)
    
    # Load certificates from the store
    try:
      self.certificates =  self.load_certificates()
    except Exception as e:
      print("Error loading certificates from store: ", e)
      self.certificates = {}
    
  def add_certificate(self, certificate: x509.Certificate) -> bool:
    # Verify certicate is valid and not expired
    if not certificate.not_valid_before_utc <= datetime.datetime.now(tz=pytz.utc) <= certificate.not_valid_after_utc:
      raise ValueError("Certificate is not valid or has expired")

    # Verify certificate is not already in the store
    if self.get_certificate(certificate.subject) is not None:
      raise ValueError("Certificate is already in the store")

    # Save certificate to store
    with open(os.path.join(self.store_path, f"{certificate.subject}.pem"), "wb") as cert_file:
      cert_file.write(certificate.public_bytes(serialization.Encoding.PEM))

    return True
  
  def load_certificates(self):
    # Check that the store path exists.
    if not os.path.exists(self.store_path):
      return {}
    
    # Load certificates from the store
    certificates = {}
    for cert_file in os.listdir(self.store_path):
      
      # Skip non-certificate files
      if not cert_file.endswith(".pem"):
        next

      # Load certificate from file
      with open(os.path.join(self.store_path, cert_file), "rb") as cert_file:
        certificate = x509.load_pem_x509_certificate(cert_file.read(), default_backend())
        
      # Verify certificate is not expired
      if not certificate.not_valid_before_utc <= datetime.datetime.now(tz=pytz.utc) <= certificate.not_valid_after_utc:
        print("Certificate with subject ", certificate.subject, " is not valid or has expired. Removing from store...")
       
        # Delete certificate file for expired certificate
        os.remove(os.path.join(self.store_path, cert_file))
        next
      
      # Add certificate to store
      certificates[certificate.subject] = certificate
      
      self.certificates = certificates
      
    return self.certificates # Return certificates
  
  def get_certificate(self, subject):
    return self.certificates.get(subject, None)
  
  