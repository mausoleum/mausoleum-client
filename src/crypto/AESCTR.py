#!/usr/bin/env python

"""
Sane wrapper around Crypto.Cipher.AES in CTR mode.
"""

from Crypto.Cipher import AES
from BlockCipher import BlockCipher, BLOCK_SIZE, NONCE_SIZE

class AESCTR(BlockCipher):
    """
    AESCTR provides a sane wrapper (read: performing padding) around
    Crypto.Cipher.AES so that the cryptographic primatives can
    actually be used.
    """
    def __init__(self, key, nonce):
        super(AESCTR, self).__init__()
        # Enforce 32-byte key and 16-byte nonce
        if len(key) != BLOCK_SIZE or len(nonce) != NONCE_SIZE:
            error = 'AESCTR keys must be %d-bytes, and nonce must be %d-bytes' \
                % (BLOCK_SIZE, NONCE_SIZE)
            raise Exception(error)
        self.cipher = AES.new(key, AES.MODE_CTR, counter = lambda: nonce)
    
    def encrypt(self, data):
        """
        Pad, then encrypt, the given data with AES-CTR.
        """
        return self.cipher.encrypt(BlockCipher.pad(data))

    def decrypt(self, data):
        """
        Decrypt, then unpad, the given data with AES-CTR.
        """
        return BlockCipher.unpad(self.cipher.decrypt(data))
    
