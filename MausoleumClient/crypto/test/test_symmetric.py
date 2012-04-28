import sys
sys.path.append('..')

import unittest

from crypto.symmetric import AESCTR
from crypto.cipher import BlockCipher

class TestAESCTR(unittest.TestCase):

    def setUp(self):
        (key, nonce) = BlockCipher.generate_ivs()
        self.enc = AESCTR(key, nonce)
        self.dec = AESCTR(key, nonce)

    def test_canDecryptOwnCrypto(self):
        plaintext = "Does PyCrypto actually work in AES-CTR mode?"
        ciphertext = self.enc.encrypt(plaintext)
        decrypttext = self.dec.decrypt(ciphertext)
        self.assertTrue(plaintext == decrypttext)

if __name__ == '__main__':
    unittest.main()
