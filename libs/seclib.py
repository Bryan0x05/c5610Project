import os
import typing
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
import logging

if typing.TYPE_CHECKING:
    import netlib # avoids circular import

USERPATH =f"/usrs/{{user}}.pkl"

class keyRing():
    '''Key ring for public key infrastructure'''

    def __init__(self):
        # TODO: URI might be a tuple instead of a str
        # TODO: Might want timestamp for expiration?
        # keys : { user_pub_key, uri , nodeType(?),status( (!)valid ) }
        self.keys: typing.Dict[ bytes, typing.Tuple[ str, "netlib.nodeType", bool ] ] = dict()
    
    def has( self, key : bytes ) -> bool:
        if key in self.keys.keys():
            return True
        return False

    def add( self, key : bytes, uri : str, type : "netlib.nodeType" ):
        if self.has(key) == True:
            logging.warning("ERR: add, adding a key that already exists")
            return False
        # assume  if we are adding a key, its status is true. 
        self.keys[ key ] = ( uri, type, True )
        return True
    
    def revoke( self, key : bytes):
        ''' Set a key status to false'''
        # NOTE: may just want a delete operation instead?
        if self.has(key) == False:
            logging.warning("ERR: revoke, tried revoking a non-existent key")
            return False
        # python tuples are imututable, we get old one and format an updated one
        keyEntry: typing.Tuple[str, "netlib.nodeType" ] = self.keys[key][0:2]
        # foramt new tuple with the revoked status
        newKeyEntry: tuple[str, "netlib.nodeType", typing.Literal[False]] = (*keyEntry, False)
        self.keys[key] = newKeyEntry
        return True
    def dele( self, key : bytes ):
        ''' Delete a key entry'''
        if self.has(key):
            self.keys.pop( key )
            return True
        logging.warning("ERR: dele, Tried deleting a non-existent key")
        return False
    
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
    def getUserPath( user):
        ''' Fills in the blank on the userpath'''
        return USERPATH.format(user=user)
    
    @staticmethod
    def generatePKCKeys() -> tuple[ rsa.RSAPublicKey, rsa.RSAPrivateKey ]:
        ''' Generate public and private key pair'''
        priKey = rsa.generate_private_key( # type : ignore
            public_exponent=65537,
            key_size=2048
        )
        return priKey.public_key(),priKey
    
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