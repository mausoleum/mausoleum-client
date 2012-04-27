#!/usr/bin/env python

"""
Sane wrapper around Crypto.Cipher.PKCS1_OAEP and
Crypto.Signature.PKCS1_PSS backed by RSA keys
"""

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_PSS
from Crypto.Hash import SHA512

class PKCSOne(object):
    """
    This class provides a sane, uniform API for accessing the PKCS1
    algorithsm for cryptography, namely OAEP (Optimal Asymmetric
    Encryption Padding) encryption/decryption and PSS (Probabilistic
    Signature Scheme) signing/verification.

    When constructed, this class must be given the necessary keys for
    operation.  If a key is omitted, attempting to perform an
    operation that requires it will result in an Exception.
    """
    def __init__(self, public_key, private_key):
        self.public_rsa = self.private_rsa = None
        if public_key is not None:
            self.public_rsa = RSA.importKey(public_key)
        if private_key is not None:
            self.private_rsa = RSA.importKey(private_key)
    
    def sign(self, data):
        """
        Sign the given data with PKCS1-PSS, using the private key. The
        data will be hashed with SHA512.
        """
        if self.private_rsa is None:
            raise Exception("Cannot sign given data, no private RSA key present")
        hasher = SHA512.new()
        hasher.update(data)
        signer = PKCS1_PSS.new(self.private_rsa)
        return signer.sign(hasher)

    def verify(self, data, possible_signature):
        """
        Verify the signature presented for the given data matches
        expectations using PKCS1-PSS, with a SHA512 hash.
        """
        if self.public_rsa is None:
            raise Exception("Cannot verify given data, no public RSA key present")
        hasher = SHA512.new()
        hasher.update(data)
        verifier = PKCS1_PSS.new(self.public_rsa)
        return verifier.verify(hasher, possible_signature)

    def encrypt(self, data):
        """
        Encrypt the given data with PKCS1-OAEP.
        """
        if self.public_rsa is None:
            raise Exception("Cannot encrypt given data, no public RSA key present")
        cipher = PKCS1_OAEP.new(self.public_rsa)
        return cipher.encrypt(data)

    def decrypt(self, data):
        """
        Decrypt the given data with PKCS1-OAEP.
        """
        if self.private_rsa is None:
            raise Exception("Cannot decrypt given data, no private RSA key present")
        cipher = PKCS1_OAEP.new(self.private_rsa)
        return cipher.decrypt(data)
