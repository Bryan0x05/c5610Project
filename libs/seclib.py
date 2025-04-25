import os
import typing
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import logging

if typing.TYPE_CHECKING:
    import netlib # avoids circular import

USERPATH =f"/usrs/{{user}}.pkl"

class keyRing():
    '''Key ring for public key infrastructure'''

    def __init__(self):
        # * { uri : ( pub_key , nodeType ) }
        self.keys: typing.Dict[  str, typing.Tuple[ rsa.RSAPublicKey, "netlib.nodeType", bool ] ] = dict()
    
    def has( self, uri : str ) -> bool:
        if uri in self.keys.keys():
            return True
        return False

    def add( self, uri : str, key :  rsa.RSAPublicKey, type : "netlib.nodeType", cert : bool = False ):
        if self.has(uri) == True:
            logging.warning("ERR: add, adding a key that already exists")
            return False
        # assume  if we are adding a key, its status is true. 
        self.keys[ uri ] = ( key, type, cert )
        return True
    
    def delete( self, uri : str ):
        ''' Delete a key entry'''
        if self.has(uri):
            self.keys.pop( uri )
            return True
        logging.warning("WARN: delete, Tried deleting a non-existent uri")
        return False
    
    def updateKey( self, uri : str, newCert : bool ):
        try:
            oldInfo = self.keys.pop( uri )
            self.add( uri, oldInfo[0],  oldInfo[1], newCert )
        except:
            return False
        return True
    
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
            key_size=4096,
            backend=default_backend() # ! Generates errors if the optional ("optional") backend is not set.
        )
        return priKey.public_key(), priKey  # type:ignore
    
    @staticmethod
    def generateCompressionKey() -> bytes:
        f =   Fernet.generate_key()
        return f
    
    @staticmethod
    def compress( key : bytes, data : bytes):
        k = Fernet( key )
        return k.encrypt( data )
    
    @staticmethod
    def uncompress( key : bytes, data : bytes ) -> str:
        k = Fernet( key )
        plainByteText : bytes = k.decrypt( data )
        return plainByteText.decode()
    
    @staticmethod
    def encrypt( key : rsa.RSAPublicKey, plaintext: bytes) -> bytes:
        '''Encrypt data using the provided key, returns ciphertext'''
        # padding here means adding randomness
        cipherTextBytes =  key.encrypt( plaintext, padding.OAEP(
            mgf=padding.MGF1( algorithm= hashes.SHA256()), # mask generation
            algorithm=hashes.SHA256(), # main hash func
            label=None
        ))
        # TODO: Wrap in a custom exeception that can be caught in netlib, and user informed
        if cipherTextBytes == None: raise BaseException("Encrpyt message failed")
        return bytes(cipherTextBytes)
    
    @staticmethod
    def serializePubKey( key : rsa.RSAPublicKey ) -> bytes:
        keyBytes = key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        if keyBytes == None: raise Exception("SerializePubKey failed")
        return bytes(keyBytes)

    @staticmethod
    def deserializePubKey( key : bytes ) ->  rsa.RSAPublicKey:
        keypub = serialization.load_pem_public_key(
            key,
            backend=default_backend()
        )
        if isinstance( keypub, rsa.RSAPublicKey):
            return keypub
        # TODO: Wrap custom error that can be caught, and user informed?
        raise Exception("SecurityManager failed to deserialize key")
    
    @staticmethod
    def decrypt( key : rsa.RSAPrivateKey, ciphertext: bytes ) -> bytes:
        '''Converts cipher text to plaintext'''
        plaintextBytes = key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        ))
        # TODO: Wrap a custom arrow that can be caught by read message to inform the user
        if plaintextBytes == None: raise Exception("decryptig message... failed!")
        return bytes(plaintextBytes)

if __name__ == "__main__":
    pass