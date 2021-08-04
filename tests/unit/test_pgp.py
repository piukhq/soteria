from unittest import TestCase

from pgpy import PGPUID, PGPKey, PGPMessage
from pgpy.constants import CompressionAlgorithm, HashAlgorithm, KeyFlags, PubKeyAlgorithm, SymmetricKeyAlgorithm

from soteria.encryption import PGP


class TestPGP(TestCase):
    def test_pgp_encryption_empty_key(self):
        with self.assertRaises(ValueError):
            PGP(b"")

    def test_pgp_encryption_bad_key(self):
        with self.assertRaises(ValueError):
            PGP(b"not a real key")

    def test_pgp_encryption_valid_key(self):
        # intentionally weak key size to save time spent in the keygen
        skey = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 1024)
        uid = PGPUID.new("Test UID")
        skey.add_uid(
            uid,
            usage={KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage},
            hashes=[HashAlgorithm.SHA256],
            ciphers=[SymmetricKeyAlgorithm.AES256],
            compression=[CompressionAlgorithm.ZIP],
        )
        pkey = skey.pubkey
        pgp = PGP(bytes(pkey))

        plaintext = "test1234"
        encrypted = pgp.encrypt(plaintext)
        decrypted = skey.decrypt(PGPMessage.from_blob(encrypted)).message
        self.assertEqual(plaintext, decrypted)
