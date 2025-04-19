import os
import typing
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import logging

if typing.TYPE_CHECKING:
    import netlib # avoids circular import

USERPATH =f"/usrs/{{user}}.pkl"

class keyRing():
    '''Key ring for public key infrastructure'''

    def __init__(self):
        # { uri : ( pub_key , nodeType(?) ) }
        self.keys: typing.Dict[  str, typing.Tuple[ rsa.RSAPublicKey, "netlib.nodeType" ] ] = dict()
    
    def has( self, uri : str ) -> bool:
        if uri in self.keys.keys():
            return True
        return False

    def add( self, uri : str, key :  rsa.RSAPublicKey, type : "netlib.nodeType" ):
        if self.has(uri) == True:
            logging.warning("ERR: add, adding a key that already exists")
            return False
        # assume  if we are adding a key, its status is true. 
        self.keys[ uri ] = ( key, type )
        return True
    
    def delete( self, uri : str ):
        ''' Delete a key entry'''
        if self.has(uri):
            self.keys.pop( uri )
            return True
        logging.warning("ERR: dele, Tried deleting a non-existent uri")
        return False
    
    def __getitem__(self, uri :  str):
        return self.keys[uri]
    
class securityManager():
    '''Security Manager, stores all cryptographic functions'''
    
    def __init__(self):
        pass

    @staticmethod
    def getSalt( length = 16 ) -> bytes:
        '''produces a password salt'''
        return os.urandom( length )
    
    @staticmethod 
    def encryptPwd( pwd: str, salt : bytes, iters: int = 1_000 ) ->bytes: # type: ignore
        ''' Encypt passsword, returns the hash in bytes '''
        # TODO: Actually look into if these are good values
        kdf = PBKDF2HMAC(              # type: ignore
            algorithm=hashes.SHA256(), # hash func
            length=32,                 # byte length
            salt=salt,                 # salt (noise)
            iterations=iters,          # rounds of hashing 
        )
        return kdf.derive( pwd.encode() )# type: ignore
    
    @staticmethod
    def getUserPath( user ):
        ''' Fills in the blank on the userpath'''
        return USERPATH.format(user=user)
    
    @staticmethod
    def generatePKCKeys() -> typing.Tuple[ rsa.RSAPublicKey, rsa.RSAPrivateKey ]: # type:ignore
        ''' Generate public and private key pair'''
        priKey = rsa.generate_private_key( 
            public_exponent=65537,         
            key_size=2048,
            backend=default_backend() # this will error out otherwise despite function header stating its an optional arg
        )
        return priKey.public_key(), priKey  # type:ignore
    
    @staticmethod
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
    def serializePubKey( key : rsa.RSAPublicKey ):
        keyBytes = key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        return keyBytes

    @staticmethod
    def deserializePubKey( key : bytes ) ->  rsa.RSAPublicKey:
        keypub = serialization.load_der_public_key(
            key
        )
        # TODO: fix later
        if isinstance( keypub, rsa.RSAPublicKey):
            return keypub
        raise Exception("SecurityManager failed to deserialize key")
    
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