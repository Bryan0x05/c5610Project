import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
USERPATH =f"/usrs/{{user}}.pkl"
class securityManager():
    ''' Security Manager, stores all cryptographic functions'''
    
    def __init__(self):
        pass

    @staticmethod
    def getSalt( length = 16 ) -> bytes:
        '''produces a password salt'''
        return os.urandom( length )
    
    @staticmethod 
    def encryptPwd( pwd: str, salt : bytes, iters: int = 1_000 ) ->bytes: # type: ignore
        ''' Encypt passsword, returns the hash in bytes '''
        # Password-based key derivation function 2
        # kdf is the key derivation function
        # TODO: Actually look into if these are good values
        kdf = PBKDF2HMAC(              # type: ignore
            algorithm=hashes.SHA256(), # hash func
            length=32,                 # byte length
            salt=salt,                 # salt (noise)
            iterations=iters,          # rounds of hashing 
        )
        return kdf.derive( pwd.encode() )# type: ignore
    
    @staticmethod
    def getUserPath( user):
        ''' Fills in the blank on the userpath'''
        return USERPATH.format(user=user)
    
    @staticmethod
    def generatePKCKeys() -> tuple[ rsa.RSAPublicKey, rsa.RSAPrivateKey ]:
        ''' Generate public and private key pair'''
        priKey = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        return priKey.public_key(),priKey
    
    @staticmethod
    # TODO: IS urandom a secure number generator?
    # TODO: See if have need of associated data
    def encrypt( key : rsa.RSAPublicKey, plaintext: bytes ):
        '''Encrypt data using the provided key, returns ciphertext'''
        # padding here means adding randomness
        cipherText =  key.encrypt( plaintext, padding.OAEP(
            mgf=padding.MGF1( algorithm= hashes.SHA256()), # mask generation
            algorithm=hashes.SHA256(), # main hash func
            label=None
        ))
        return cipherText
    
    @staticmethod
    def decrypt( key : rsa.RSAPrivateKey, ciphertext: bytes ):
        '''Converts cipher text to plaintext'''
        plaintext = key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        ))
        return plaintext


if __name__ == "__main__":
    pass