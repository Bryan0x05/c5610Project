import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
USERPATH =f"/usrs/{{user}}.pkl"
class securityManager():
    ''' Security Manager, stores all cryptographic functions'''
    
    def __init__(self):
        pass

    @staticmethod
    def getSalt( length = 16 ) -> bytes:
        return os.urandom( length )
    
    @staticmethod
    def encryptPwd( pwd: str, salt : bytes, iters: int = 1_000 )->bytes:
        # Password-based key derivation function 2
        # kdf is the key derivation function
        # TODO: Actually look into if these are good values
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(), # hash func
            length=32,                 # byte length
            salt=salt,                 # salt (noise)
            iterations=iters,          # rounds of hashing
            backend=default_backend()  # specifically here to see if this gets pywright to stop
        )
        return kdf.derive( pwd.encode() )

    
    @staticmethod
    def getUserPath( user):
        return USERPATH.format(user=user)
    
    @staticmethod
    def generatePKCKeys() -> tuple[bytes, bytes]:
        # TODO: eval if these values make sense
        pubKey = AESGCM.generate_key(bit_length=512)  # AES256 requires 512-bit keys for SIV
        priKey = AESGCM.generate_key(bit_length=512)
        return pubKey,priKey
    
    @staticmethod
    # TODO: IS urandom a secure number generator?
    # TODO: See if have need of assoicated data
    def encrypt( key : bytes, data: bytes, nonce : bytes = os.urandom(16), assoicatedData = None ):
        cipherText =  AESGCM(key).encrypt( nonce , data, assoicatedData )
        return cipherText, nonce
    
    @staticmethod
    def decrypt( key : bytes, data: bytes, nonce: bytes, assoicatedData = None ):
        return AESGCM(key).decrypt( nonce, data, assoicatedData )

if __name__ == "__main__":
    pass