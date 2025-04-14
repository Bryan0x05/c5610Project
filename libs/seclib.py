import os
import typing
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
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
    def generatePKCKeys() -> typing.Tuple[bytes, bytes]:
        ''' Generate public and private key pair'''
        # TODO: eval if these values make sense
        pubKey: bytes = AESGCM.generate_key(bit_length=512)  # AES256 requires 512-bit keys for SIV
        priKey: bytes = AESGCM.generate_key(bit_length=512)
        return pubKey,priKey
    
    @staticmethod
    # TODO: IS urandom a secure number generator?
    # TODO: See if have need of associated data
    # TODO: data cannot be greater than 64 bytes! (see max size of AESGCM)
    def encrypt( key : bytes, data: bytes, nonce : bytes = os.urandom(16), assoicatedData = None ):
        ''' Encrypt data using the provided key, returns ciphertext and nonce'''
        cipherText =  AESGCM(key).encrypt( nonce , data, assoicatedData )
        return cipherText, nonce
    
    @staticmethod
    def decrypt( key : bytes, data: bytes, nonce: bytes, assoicatedData = None ):
        ''' Decrypt data with the provided key and nonce'''
        return AESGCM(key).decrypt( nonce, data, assoicatedData )
    
    @staticmethod
    def validateSignature( sig : bytes, nonce: bytes, key : bytes, assoicatedData = None):
        '''Attempt to eval provided signature (w/ nonce that was used) with given key'''
        # sig should be CA_pub_key.encrypt( user_pub_key)
        
        # Decrypt with CA private key.
        # TODO: Double check that we actually mak private, public key pairs correctly.
        aesgcm = AESGCM(key)
        # return user_pub_key, another function will look it up in the public key rin
        return aesgcm.decrypt( nonce, sig, assoicatedData)
        

if __name__ == "__main__":
    pass