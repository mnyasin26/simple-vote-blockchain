from Blockchain import *
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
import base64

blockchain = Blockchain()

class Vote:
    def __init__(self, public_key, candidate_id):
        self.public_key = public_key
        self.candidate_id = candidate_id
        self.signature = None

    def to_dict(self):
        if self.signature is None:
            raise Exception('Vote must be signed before execution')
        return {
            'public_key': self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8'),
            'candidate_id': self.candidate_id,
            'signature': base64.b64encode(self.signature).decode('utf-8')
        }

    def sign_vote(self, private_key):
        message = f"{self.public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode('utf-8')}{self.candidate_id}".encode('utf-8')

        print(f"Message: {message}")
        self.signature = private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        print(f"Signature: {self.signature}")

    @staticmethod
    def validate_vote(vote):
        try:
            public_key = serialization.load_pem_public_key(
                vote['public_key'].encode('utf-8')
            )

            print(f"Public key: {public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode('utf-8')}")

            signature = base64.b64decode(vote['signature'])

            print(f"Signature: {signature}")

            message = f"{vote['public_key']}{vote['candidate_id']}".encode('utf-8')

            print(f"Message: {message}")
            
            result = False

            try:
                public_key.verify(
                    signature,
                    message,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                result = True
            except Exception as e:
                print(f"Failed to verify vote: {e}")

            return result
        except Exception as e:
            print(f"Error during vote validation: {e}")
            return False
        
        
        

