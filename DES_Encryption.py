from Cryptodome.Cipher import DES
import binascii

def encryption(des, P, key):
    while len(P) % 8 != 0:
        P += ' '
    P = P.encode()
    C = des.encrypt(P)
    C = binascii.hexlify(C)
    C = C.decode()
    return C

def decryption(des, C, key):
    C = binascii.unhexlify(C)
    P = des.decrypt(C)
    P = P.decode().strip()
    return P

key = input("Enter key:")
P = input("Enter plain text:")
print("Plaintext:", P)
key = key.encode()
des_cipher = DES.new(key, DES.MODE_ECB)
C = encryption(des_cipher, P, key)
print("Ciphertext:", C)
P1 = decryption(des_cipher, C, key)
print("Plaintext:", P1)
