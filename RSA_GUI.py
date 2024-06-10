from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import base64
import tkinter as tk
from tkinter import messagebox, filedialog

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

# GUI application
class SecureTextApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("SecureText: RSA Encryption/Decryption")
        self.geometry("600x400")

        self.label = tk.Label(self, text="SecureText: RSA Encryption and Decryption", font=("Helvetica", 16))
        self.label.pack(pady=20)

        self.generate_button = tk.Button(self, text="Generate and Save RSA Keys", command=self.generate_keys)
        self.generate_button.pack(pady=10)

        self.encrypt_button = tk.Button(self, text="Encrypt a Message", command=self.encrypt_message)
        self.encrypt_button.pack(pady=10)

        self.decrypt_button = tk.Button(self, text="Decrypt a Message", command=self.decrypt_message)
        self.decrypt_button.pack(pady=10)

        self.text_area = tk.Text(self, wrap='word', height=10)
        self.text_area.pack(pady=20)

    def generate_keys(self):
        private_key, public_key = generate_keys()
        save_keys(private_key, public_key)
        messagebox.showinfo("Keys Generated", "Keys generated and saved successfully.")

    def encrypt_message(self):
        _, public_key = load_keys()
        message = self.text_area.get("1.0", tk.END).strip()
        if message:
            ciphertext = encrypt_message(public_key, message)
            encoded_ciphertext = base64.b64encode(ciphertext).decode()
            self.text_area.delete("1.0", tk.END)
            self.text_area.insert(tk.END, encoded_ciphertext)
            messagebox.showinfo("Encryption Success", "Message encrypted successfully.")
        else:
            messagebox.showwarning("Input Error", "Please enter a message to encrypt.")

    def decrypt_message(self):
        private_key, _ = load_keys()
        ciphertext = self.text_area.get("1.0", tk.END).strip()
        if ciphertext:
            decoded_ciphertext = base64.b64decode(ciphertext)
            try:
                plaintext = decrypt_message(private_key, decoded_ciphertext)
                self.text_area.delete("1.0", tk.END)
                self.text_area.insert(tk.END, plaintext)
                messagebox.showinfo("Decryption Success", "Message decrypted successfully.")
            except Exception as e:
                messagebox.showerror("Decryption Error", "Decryption failed. Ensure the encrypted text and key are correct.")
        else:
            messagebox.showwarning("Input Error", "Please enter a message to decrypt.")

if __name__ == "__main__":
    app = SecureTextApp()
    app.mainloop()
