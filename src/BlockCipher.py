#!/usr/bin/env python

"""
This file contains the BlockCipher base class, which provides many
convenience functions for running complex block ciphers.
"""

import os

BLOCK_SIZE = 32
NONCE_SIZE = BLOCK_SIZE / 2

class BlockCipher(object):
    """
    Base class for all Block Ciphers.  This class provides sane
    defaults for the Block Size and Nonce Size, as well as static
    methods to perform padding, unpadding, and generating an
    initialization vector (key and nonce) for the cipher.
    """
    def __init__(self):
        pass

    @staticmethod
    def pad(data):
        """
        Take the incoming data, add a 1 bit, then pad it out with 0s
        until reaching the block size.  This guarantees that cipher
        will operate correctly and the data unambiguous.
        """
        data += '\x80'
        num_blocks = len(data) // BLOCK_SIZE + 1
        
        data += '\x00' * (num_blocks * BLOCK_SIZE - len(data))

        return data

    @staticmethod
    def unpad(data):
        """
        Take the incoming data and unpad it, reversing the pad()
        function.  This is needed to recover the original data after
        decryption.
        """
        return data[0:data.rfind('\x80')]

    @staticmethod
    def generate_ivs():
        """
        Generate a block-size key and a nonce-size nonce
        initialization vector.
        """
        return (os.urandom(BLOCK_SIZE), os.urandom(NONCE_SIZE))
