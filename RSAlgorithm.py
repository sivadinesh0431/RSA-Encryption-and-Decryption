from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import base64



# Key generation
def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key

# Save keys to files
def save_keys(private_key, public_key):
    pem_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open('private_key.pem', 'wb') as f:
        f.write(pem_private_key)
    
    with open('public_key.pem', 'wb') as f:
        f.write(pem_public_key)

# Load keys from files
def load_keys():
    with open('private_key.pem', 'rb') as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
        )
    
    with open('public_key.pem', 'rb') as f:
        public_key = serialization.load_pem_public_key(f.read())
    
    return private_key, public_key

# Encrypt message
def encrypt_message(public_key, message):
    ciphertext = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

# Decrypt message
def decrypt_message(private_key, ciphertext):
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext.decode()

# Command-line interface
def main():
    print("SecureText: Text Encryption and Decryption using RSA")
    print("1. Generate and save RSA keys")
    print("2. Encrypt a message")
    print("3. Decrypt a message")
    choice = input("Choose an option (1/2/3): ")

    if choice == '1':
        private_key, public_key = generate_keys()
        save_keys(private_key, public_key)
        print("Keys generated and saved successfully.")
    
    elif choice == '2':
        _, public_key = load_keys()
        message = input("Enter the message to encrypt: ")
        ciphertext = encrypt_message(public_key, message)
        print("Encrypted message:", base64.b64encode(ciphertext).decode())

    elif choice == '3':
        private_key, _ = load_keys()
        ciphertext = input("Enter the message to decrypt (base64 encoded): ")
        decoded_ciphertext = base64.b64decode(ciphertext)
        try:
            plaintext = decrypt_message(private_key, decoded_ciphertext)
            print("Decrypted message:", plaintext)
        except Exception as e:
            print("Decryption failed. Ensure the encrypted text and key are correct.")
    else:
        print("Invalid choice. Please select 1, 2, or 3.")

if __name__ == "__main__":
    main()
