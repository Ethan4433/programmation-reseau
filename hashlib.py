from base64 import b64encode, b64decode
import hashlib
from Cryptodome.Cipher import AES
import os
from Cryptodome.Random import get_random_bytes

def encrypt(plain_text, password):
    # generate a random salt
    salt = get_random_bytes(AES.block_size)

    # use the Scrypt KDF to get a private key from the password
    private_key = hashlib.scrypt(
        password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)

    # create cipher config
    cipher_config = AES.new(private_key, AES.MODE_GCM)

    # return a dictionary with the encrypted text
    cipher_text, tag = cipher_config.encrypt_and_digest(bytes(plain_text, 'utf-8'))
    return {
        'cipher_text': b64encode(cipher_text).decode('utf-8'),
        'salt': b64encode(salt).decode('utf-8'),
        'nonce': b64encode(cipher_config.nonce).decode('utf-8'),
        'tag': b64encode(tag).decode('utf-8')
    }


def decrypt(enc_dict, password):
    # decode the dictionary entries from base64
    salt = b64decode(enc_dict['salt'])
    cipher_text = b64decode(enc_dict['cipher_text'])
    nonce = b64decode(enc_dict['nonce'])
    tag = b64decode(enc_dict['tag'])
    

    # generate the private key from the password and salt
    private_key = hashlib.scrypt(
        password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)

    # create the cipher config
    cipher = AES.new(private_key, AES.MODE_GCM, nonce=nonce)

    # decrypt the cipher text
    decrypted = cipher.decrypt_and_verify(cipher_text, tag)

    return decrypted

def hash_sha256(info):
    return hashlib.sha256(info.encode()).hexdigest()

def menu():
    print("MENU\n=======\n\t1. Chiffrer l'info\n\t2. Dechiffrer l'info\n\t3. Hacher une info\n\t4. Vérifier une info")
    choix = input("\n\tVotre choix ?")
    return choix

def main():
    choix = menu()
    if choix == "1":
        password = input("Mot de passe: ")
        plain_text = input("Texte à chiffrer:")
        encrypted = encrypt(plain_text, password)
        print(encrypted)
    elif choix == "2":
        password = input("Mot de passe: ")
        cipher_text = input("Texte chiffré :")
        salt = input("Salt :")
        tag = input("Tag :")
        nonce = input("Nonce :")
        encrypted = { 'cipher_text': cipher_text, 'salt': salt, 'nonce': nonce, 
        'tag': tag }
        decrypted = decrypt(encrypted, password)
        print(bytes.decode(decrypted))
    elif choix == "3":
        info = input("Information à hash :")
        print(f"Empreinte calculée: {hash_sha256(info)}")
    elif choix == "4":
        info = input("Entrez la donnée à vérifier :")
        empreinte = input("Entrez l'empreinte :")
        empreinte_calculee = hash_sha256(info)
        print(f"Empreinte valide: {empreinte == empreinte_calculee}")

main()
