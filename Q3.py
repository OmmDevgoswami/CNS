from Crypto.Cipher import AES
import base64

key = b'ThisIsASecretKey'

def pad(text):
    return text + (16 - len(text) % 16) * ' '

def encrypt(message):
    cipher=AES.new (key, AES.MODE_ECB)
    padded = pad(message)
    encrypted = cipher.encrypt(padded.encode())
    return base64.b64encode(encrypted).decode()

def decrypt(ciphertext):
    cipher = AES.new(key, AES.MODE_ECB)
    decoded = base64.b64decode(ciphertext)
    decrypted = cipher.decrypt(decoded).decode()
    return decrypted.rstrip()

def main():
    message = "Hello"
    print("Original: ",message)
    cipher_text = encrypt(message)
    print("Encrypted: ",cipher_text)
    plain_text = decrypt(cipher_text)
    print("Decrypted: ",plain_text)

if __name__ == "__main__":
    main()

'''
Output--
Original:  Hello
Encrypted:  aleYspAO0PcvlkawhNJMdg==
Decrypted:  Hello
'''