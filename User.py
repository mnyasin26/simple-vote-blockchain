import os
import json
import base64
import secrets
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from sqlalchemy import Column, Integer, String
from sqlalchemy.orm import sessionmaker
from connection import Base, engine, SessionLocal
from Vote import Vote  # Import the Vote class from the appropriate module
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet

KDF_ALGORITHM = hashes.SHA256()
KDF_LENGTH = 32
KDF_ITERATIONS = 120000

class UserModel(Base):
    __tablename__ = 'Users'
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(255), unique=True, index=True)
    password_hash = Column(String(255))

Base.metadata.create_all(bind=engine)

def pad_password(password: str) -> bytes:
    return base64.urlsafe_b64encode(f"{password:<32}".encode("utf-8"))

def encrypt(plaintext: str, password: str) -> (bytes, bytes):
    # Derive a symmetric key using the passsword and a fresh random salt.
    salt = secrets.token_bytes(16)
    kdf = PBKDF2HMAC(
        algorithm=KDF_ALGORITHM, length=KDF_LENGTH, salt=salt,
        iterations=KDF_ITERATIONS)
    key = kdf.derive(password.encode("utf-8"))

    print(f"password: {password}")
    print(f"Key: {key}")

    # Encrypt the message.
    f = Fernet(base64.urlsafe_b64encode(key))
    ciphertext = f.encrypt(plaintext.encode("utf-8"))

    return ciphertext, salt

def decrypt(ciphertext: bytes, password: str, salt: bytes) -> str:
    # Derive the symmetric key using the password and provided salt.
    kdf = PBKDF2HMAC(
        algorithm=KDF_ALGORITHM, length=KDF_LENGTH, salt=salt,
        iterations=KDF_ITERATIONS)
    key = kdf.derive(password.encode("utf-8"))

    print(f"password: {password}")
    print(f"Key: {key}")

    # Decrypt the message
    f = Fernet(base64.urlsafe_b64encode(key))
    print("test")
    plaintext = f.decrypt(ciphertext.decode("utf-8"))
    print("test2")

    return plaintext.decode("utf-8")

class User:
    def __init__(self, username, password=None):
        self.username = username
        self.password_hash = generate_password_hash(password) if password else None
        self.generate_key_pair()

    def generate_key_pair(self):
        private_key_path = f'private_keys/{self.username}_private_key.pem'

        if os.path.exists(private_key_path):
            print("private key already exists and cannot be regenerated.")
            return

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        # public_key = private_key.public_key()

        with open(private_key_path, 'wb') as private_file:
            private_file.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                )
            )

    def save_keys(self, password):
        private_key_path = f'private_keys/{self.username}_private_key.pem'
        salt_path = f'salts/{self.username}_salt.bin'

        if os.path.exists(private_key_path):
            with open(private_key_path, 'r') as private_file:
                private_key_data = private_file.read()

            print(f"Private key: {private_key_data}")

            encrypted_private_key, salt = encrypt(private_key_data, password)
            print(f"Encrypted private key: {encrypted_private_key}")
            print(f"Salt: {salt}")

            with open(private_key_path, 'wb') as private_file:
                private_file.write(encrypted_private_key)

            with open(salt_path, 'wb') as salt_file:
                salt_file.write(salt)

    def load_private_key(self, password):
        private_key_path = f'private_keys/{self.username}_private_key.pem'
        salt_path = f'salts/{self.username}_salt.bin'

        if os.path.exists(private_key_path):
            with open(private_key_path, 'rb') as private_file:
                encrypted_private_key = private_file.read()

            print(f"Encrypted private key: {encrypted_private_key}")

            with open(salt_path, 'rb') as salt_file:
                salt = salt_file.read()

            print(f"Salt: {salt}")

            try:
                decrypted_private_key = decrypt(encrypted_private_key, password, salt)
                print(decrypted_private_key)
                private_key = serialization.load_pem_private_key(
                    decrypted_private_key.encode("utf-8"),
                    password=None,
                    backend=default_backend()
                )
                print(f"Private key loaded for user {self.username}")

                # public_key = private_key.public_key()
                # print(f"Public key: {public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode('utf-8')}")
                return private_key
            except Exception as e:
                print(f"Failed to decrypt private key: {e}")
                return None
        else:
            print(f"Private key for user {self.username} does not exist.")
            return None
        
    def load_public_key(self, password):
        private_key = self.load_private_key(password)
        if private_key:
            return private_key.public_key()
        else:
            return None

    def save_to_db(self, password):
        try:
            db = SessionLocal()
            db_user = UserModel(username=self.username, password_hash=self.password_hash)
            db.add(db_user)
            db.commit()
            db.refresh(db_user)
            self.save_keys(password)
            return True
        except Exception as e:
            print(f"An error occurred while saving the user to the database: {e}")
        finally:
            db.close()
        return False
            

    @staticmethod
    def load_from_db(username):
        db = SessionLocal()
        db_user = db.query(UserModel).filter(UserModel.username == username).first()
        db.close()
        if db_user:
            user = User(username)
            user.password_hash = db_user.password_hash
            return user
        else:
            print(f"User {username} does not exist in the database.")
            return None

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def vote(self, candidate_id, password):
        private_key = self.load_private_key(password)
        if private_key:
            vote = Vote(private_key.public_key(), candidate_id)
            vote.sign_vote(private_key)
            return vote
        else:
            return
    

def create_user(username, password):
    user = User(username, password)
    user.save_to_db(password)

def login_user(username, password):
    user = User.load_from_db(username)
    if user and user.verify_password(password):
        print(f"User {username} logged in successfully.")
        private_key = user.load_private_key(password)
        if private_key:
            print(f"Private key for user {username} loaded successfully.")
        else:
            print("Failed to load private key.")
    else:
        print(f"Login failed for user {username}.")

if __name__ == "__main__":
    action = input("Enter 'create' to create a new user or 'login' to log in: ").strip().lower()
    username = input("Enter username: ")
    password = input("Enter password: ")

    if action == 'create':
        create_user(username, password)

    elif action == 'login':
        login_user(username, password)
    else:
        print("Invalid action.")