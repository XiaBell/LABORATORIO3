import os
import sys
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization

def generateParameters(paramFile):
    parameters = dh.generate_parameters(generator=2, key_size=2048)
    paramBytes = parameters.parameter_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.ParameterFormat.PKCS3
    )
    with open(paramFile, "wb") as f:
        f.write(paramBytes)

def generateKeys(paramFile, privKeyFile, pubKeyFile):
    with open(paramFile, "rb") as f:
        parameters = serialization.load_pem_parameters(f.read())
    
    privateKey = parameters.generate_private_key()
    publicKey = privateKey.public_key()
    
    with open(privKeyFile, "wb") as f:
        f.write(privateKey.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
        
    with open(pubKeyFile, "wb") as f:
        f.write(publicKey.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

def deriveSharedKey(privKeyFile, peerPubKeyFile, sharedKeyFile):
    with open(privKeyFile, "rb") as f:
        privateKey = serialization.load_pem_private_key(f.read(), password=None)
        
    with open(peerPubKeyFile, "rb") as f:
        peerPublicKey = serialization.load_pem_public_key(f.read())
        
    sharedSecret = privateKey.exchange(peerPublicKey)
    
    derivedKey = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'dh_key_exchange'
    ).derive(sharedSecret)
    
    with open(sharedKeyFile, "wb") as f:
        f.write(derivedKey)

def encryptFile(keyFile, inputFile, outputFile):
    with open(keyFile, "rb") as f:
        key = f.read()
        
    iv = os.urandom(16)
    cipherInstance = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptorInstance = cipherInstance.encryptor()
    
    with open(inputFile, "rb") as f:
        fileData = f.read()
        
    encryptedData = encryptorInstance.update(fileData) + encryptorInstance.finalize()
    
    with open(outputFile, "wb") as f:
        f.write(iv + encryptedData)

def decryptFile(keyFile, inputFile, outputFile):
    with open(keyFile, "rb") as f:
        key = f.read()
        
    with open(inputFile, "rb") as f:
        fileData = f.read()
        
    iv = fileData[:16]
    cipherText = fileData[16:]
    
    cipherInstance = Cipher(algorithms.AES(key), modes.CFB(iv))
    decryptorInstance = cipherInstance.decryptor()
    
    decryptedData = decryptorInstance.update(cipherText) + decryptorInstance.finalize()
    
    with open(outputFile, "wb") as f:
        f.write(decryptedData)

if __name__ == "__main__":
    action = sys.argv[1]
    if action == "genParams":
        generateParameters(sys.argv[2])
    elif action == "genKeys":
        generateKeys(sys.argv[2], sys.argv[3], sys.argv[4])
    elif action == "derive":
        deriveSharedKey(sys.argv[2], sys.argv[3], sys.argv[4])
    elif action == "encrypt":
        encryptFile(sys.argv[2], sys.argv[3], sys.argv[4])
    elif action == "decrypt":
        decryptFile(sys.argv[2], sys.argv[3], sys.argv[4])