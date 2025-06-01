import os
import base64
import pathlib
import secrets
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag


class FolderEncryptor:
    def __init__(self, password: str):
        self.password = password
        self.backend = default_backend()

    def derive_key(self, password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100_000,
            backend=self.backend
        )
        return kdf.derive(password.encode())

    def encrypt_name(self, name: str, key: bytes) -> str:
        nonce = secrets.token_bytes(12)
        aesgcm = AESGCM(key)
        encrypted = aesgcm.encrypt(nonce, name.encode(), None)
        return base64.urlsafe_b64encode(nonce + encrypted).decode()

    def decrypt_name(self, encrypted_name: str, key: bytes) -> str:
        data = base64.urlsafe_b64decode(encrypted_name.encode())
        nonce, ciphertext = data[:12], data[12:]
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, None).decode()

    def encrypt_folder(self, input_folder: str, output_folder: str):
        input_path = pathlib.Path(input_folder)
        output_path = pathlib.Path(output_folder)
        for root, dirs, files in os.walk(input_path):
            for file in files:
                full_path = pathlib.Path(root) / file
                rel_path = full_path.relative_to(input_path)

                salt = secrets.token_bytes(16)
                key = self.derive_key(self.password, salt)

                with full_path.open('rb') as f:
                    plaintext = f.read()

                aesgcm = AESGCM(key)
                nonce = secrets.token_bytes(12)
                ciphertext = aesgcm.encrypt(nonce, plaintext, None)

                # Encrypt relative path
                encrypted_rel_parts = [self.encrypt_name(part, key) for part in rel_path.parts]
                encrypted_file_path = output_path.joinpath(*encrypted_rel_parts)

                encrypted_file_path.parent.mkdir(parents=True, exist_ok=True)
                with encrypted_file_path.open('wb') as f:
                    f.write(salt + nonce + ciphertext)

    def decrypt_folder(self, input_folder: str, output_folder: str):
        input_path = pathlib.Path(input_folder)
        output_path = pathlib.Path(output_folder)

        for root, dirs, files in os.walk(input_path):
            for file in files:
                full_path = pathlib.Path(root) / file
                rel_path = full_path.relative_to(input_path)

                with full_path.open('rb') as f:
                    data = f.read()
                salt, nonce, ciphertext = data[:16], data[16:28], data[28:]

                key = self.derive_key(self.password, salt)

                try:
                    plaintext = AESGCM(key).decrypt(nonce, ciphertext, None)
                except InvalidTag:
                    print(f"[ERROR] Authentication failed for {full_path}")
                    continue

                # Decrypt relative path
                try:
                    decrypted_rel_parts = [self.decrypt_name(part, key) for part in rel_path.parts]
                    output_file_path = output_path.joinpath(*decrypted_rel_parts)
                    output_file_path.parent.mkdir(parents=True, exist_ok=True)

                    with output_file_path.open('wb') as f:
                        f.write(plaintext)
                except Exception as e:
                    print(f"[ERROR] Failed to decrypt filename for {full_path}: {e}")


if __name__ == "__main__":
    password = ""

    encryptor = FolderEncryptor(password)
    encryptor.encrypt_folder("source_folder", "encrypted_folder")

    decryptor = FolderEncryptor(password)
    decryptor.decrypt_folder("encrypted_folder", "decrypted_folder")
