from pgpy import PGPKey, PGPMessage


class PGP:
    def __init__(self, pkey_bytes):
        """
        Initialises the PGP class with the given PGP public key (bytes.)
        """
        self.pkey, *_ = PGPKey.from_blob(pkey_bytes)

    def encrypt(self, text):
        """
        Encrypts the given text (str) and returns the encrypted message (bytes.)
        Uses the public key loaded during initialisation for the encryption.
        """
        msg = PGPMessage.new(text)
        encrypted_msg = self.pkey.encrypt(msg)
        return bytes(encrypted_msg)
