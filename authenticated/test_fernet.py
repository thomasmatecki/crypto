from authenticated.fernet import Fernet, InvalidToken, num, byteblock

import pytest
import base64
import os
import time
import binascii
import struct

from cryptography.hazmat.primitives import cmac, ciphers
from cryptography.hazmat.backends import default_backend


def test_num():
  assert num([0x01]) == 1
  assert num([0xff]) == 255
  assert num([0x01, 0x00]) == 256
  assert num([0x01, 0x01]) == 257
  assert num([0xff, 0xff]) == 65535
  assert num([0x01, 0x00, 0x00]) == 65536
  assert num([0x01, 0x00, 0x01]) == 65537
  assert num([0x01, 0x00, 0x02]) == 65538
  assert num([0x01, 0x00, 0xff]) == 65791
  assert num('\x01\x00\xff') == 65791
  assert num(
    '\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00') == 338953138925153547590470800371487866880


def test_byteblock():
  assert '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01' == byteblock(1)
  assert '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff' == byteblock(255)
  assert '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00' == byteblock(256)
  assert '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x01' == byteblock(257)
  assert '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff' == byteblock(65535)
  assert '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00' == byteblock(65536)
  assert '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x01' == byteblock(65537)
  assert '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x02' == byteblock(65538)
  assert '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\xff' == byteblock(65791)
  assert '\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' == byteblock(
    338953138925153547590470800371487866880)


# noinspection PyAttributeOutsideInit
class TestFernet:

  def setup_method(self, method):
    """ setup any state tied to the execution of the given method in a
    class.  setup_method is invoked for every test method of a class.
    """
    self.key = Fernet.generate_key()
    self.fernet = Fernet(self.key)
    self._backend = default_backend()

  def test_InvalidVersionToken(self):
    ctxe = base64.urlsafe_b64encode(b'\x00' + os.urandom(54))
    with pytest.raises(InvalidToken):
      self.fernet.decrypt(ctxe)

  def test_ShortCipherText(self):
    ctxe = base64.urlsafe_b64encode(b'\x00')
    with pytest.raises(ValueError):
      self.fernet.decrypt(ctxe)

  def test_InvalidMac(self):
    msg0 = os.urandom(23)

    ctxe = self.fernet.encrypt(msg0)
    # Tamper with the MAC
    ctxd = base64.urlsafe_b64decode(ctxe)
    ctxe = base64.urlsafe_b64encode(
      ctxd[:-1] + chr(ord(ctxd[-1]) + 1)
    )

    with pytest.raises(InvalidToken):
      self.fernet.decrypt(ctxe)

    ctxe = self.fernet.encrypt(msg0)
    # Tamper with the message
    ctxd = base64.urlsafe_b64decode(ctxe)
    ctxe = base64.urlsafe_b64encode(
      ctxd[:-20] + chr(ord(ctxd[-20]) + 1) + ctxd[-20:]
    )

    with pytest.raises(InvalidToken):
      self.fernet.decrypt(ctxe)

  def test_ExpiredTimeStamp(self):
    timetolive = -10

    msg0 = os.urandom(23)

    ctxe = self.fernet.encrypt(msg0)

    with pytest.raises(InvalidToken):
      self.fernet.decrypt(ctxe, timetolive=timetolive)

  def test_EmptyMessage(self):
    msg0 = ""
    ctxe = self.fernet.encrypt(msg0)
    assert "" == self.fernet.decrypt(ctxe)

  def test_Functionality(self):
    for i in xrange(20):
      msg0 = os.urandom(6)

      ctxe = self.fernet.encrypt(msg0)
      msg1 = self.fernet.decrypt(ctxe)
      assert msg0 == msg1

    # Long Messages
    for i in xrange(1, 2000, 13):
      msg0 = os.urandom(i)

      ctxe = self.fernet.encrypt(msg0)
      msg1 = self.fernet.decrypt(ctxe)
      assert msg0 == msg1

  def test_EncryptionCorrectness(self):

    encryption_key = self.fernet._encryption_key

    iv = 16 * '\x00'

    # Ensure the hazmat and fernet ciphers produce identical ciphertexts by
    # encrypting variable length strings of all zero-bytes. Start with
    # multiples of 128 bits, then try less obvious message lengths.
    for j in xrange(16, 8, -1):
      for i in xrange(1, 10):
        msg0 = i * j * '\x00'

        ctxe = self.fernet.encrypt(msg0, iv0=iv)
        ctxd = base64.urlsafe_b64decode(ctxe)
        ctx = ctxd[25:-16]

        # Get the IV from the ciphertext
        iv = ctxd[9:25]

        # AES CTR mode cipher
        cipher = ciphers.Cipher(ciphers.algorithms.AES(encryption_key),
                                ciphers.modes.CTR(iv),
                                self._backend)

        encrypter = cipher.encryptor()
        hazmat_ctx = encrypter.update(msg0) + encrypter.finalize()

        # Ensure the ciphertexts are equivalent
        assert ctx == hazmat_ctx
        decrypter = cipher.decryptor()
        # Decrypt the ciphertext produced by fernet with the hazmat cipher
        assert msg0 == decrypter.update(ctx) + decrypter.finalize()

    def _test_vector_harness(input_ptx, expected_ctx, fernet, hazmat_cipher, iv):
      """
      For a given test vector, ensure that the fernet implementations
      and the `cryptography.hazmat` implementations both produce the
      expected values for encryption and decryption.
      """

      ctxe = fernet.encrypt(input_ptx, iv0=iv)
      ctxd = base64.urlsafe_b64decode(ctxe)

      fernet_ctx = ctxd[25:-16]

      hazmat_encryptor = hazmat_cipher.encryptor()
      hazmat_ctx = hazmat_encryptor.update(input_ptx) + hazmat_encryptor.finalize()

      assert fernet_ctx == hazmat_ctx == expected_ctx

      hazmat_decryptor = hazmat_cipher.decryptor()

      hazmat_ptx = hazmat_decryptor.update(hazmat_ctx) + hazmat_decryptor.finalize()
      fernet_ptx = fernet.decrypt(ctxe)

      assert fernet_ptx == hazmat_ptx == input_ptx

    # Verify test vectors F.5.1 CTR-AES128.Encrypt and F.5.2 CTR-AES128.Decrypt from
    # NIST Special Pub 800-38A

    encryption_key = binascii.unhexlify("2b7e151628aed2a6abf7158809cf4f3c")
    iv = binascii.unhexlify("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")

    test_ptx = "".join(map(binascii.unhexlify, [
      "6bc1bee22e409f96e93d7e117393172a",
      "ae2d8a571e03ac9c9eb76fac45af8e51",
      "30c81c46a35ce411e5fbc1191a0a52ef",
      "f69f2445df4f9b17ad2b417be66c3710"
    ]))

    test_ctx = "".join(map(binascii.unhexlify, [
      "874d6191b620e3261bef6864990db6ce",
      "9806f66b7970fdff8617187bb9fffdff",
      "5ae4df3edbd5d35e5b4f09020db03eab",
      "1e031dda2fbe03d1792170a0f3009cee"
    ]))

    # Monkey-mock fernet encryptor - Yikes!
    self.fernet._encryption_key = encryption_key
    _test_vector_harness(input_ptx=test_ptx,
                         expected_ctx=test_ctx,
                         fernet=self.fernet,
                         hazmat_cipher=ciphers.Cipher(ciphers.algorithms.AES(encryption_key),
                                                      ciphers.modes.CTR(iv),
                                                      self._backend),
                         iv=iv)

    # Verify AES Counter test vectors from RFC 3686

    # 1
    encryption_key = binascii.unhexlify("AE6852F8121067CC4BF7A5765577F39E")
    iv = binascii.unhexlify("00000030000000000000000000000001")
    test_ptx = binascii.unhexlify("53696E676C6520626C6F636B206D7367")
    test_ctx = binascii.unhexlify("E4095D4FB7A7B3792D6175A3261311B8")

    self.fernet._encryption_key = encryption_key
    _test_vector_harness(input_ptx=test_ptx,
                         expected_ctx=test_ctx,
                         fernet=self.fernet,
                         hazmat_cipher=ciphers.Cipher(ciphers.algorithms.AES(encryption_key),
                                                      ciphers.modes.CTR(iv),
                                                      self._backend),
                         iv=iv)

    # 2
    encryption_key = binascii.unhexlify("7E24067817FAE0D743D6CE1F32539163")
    iv = binascii.unhexlify("006CB6DBC0543B59DA48D90B00000001")
    test_ptx = binascii.unhexlify("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
    test_ctx = binascii.unhexlify("5104A106168A72D9790D41EE8EDAD388EB2E1EFC46DA57C8FCE630DF9141BE28")

    self.fernet._encryption_key = encryption_key
    _test_vector_harness(input_ptx=test_ptx,
                         expected_ctx=test_ctx,
                         fernet=self.fernet,
                         hazmat_cipher=ciphers.Cipher(ciphers.algorithms.AES(encryption_key),
                                                      ciphers.modes.CTR(iv),
                                                      self._backend),
                         iv=iv)

    # 3
    encryption_key = binascii.unhexlify("7691BE035E5020A8AC6E618529F9A0DC")
    iv = binascii.unhexlify("00E0017B27777F3F4A1786F000000001")
    test_ptx = binascii.unhexlify("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20212223")
    test_ctx = binascii.unhexlify("C1CF48A89F2FFDD9CF4652E9EFDB72D74540A42BDE6D7836D59A5CEAAEF3105325B2072F")

    self.fernet._encryption_key = encryption_key
    _test_vector_harness(input_ptx=test_ptx,
                         expected_ctx=test_ctx,
                         fernet=self.fernet,
                         hazmat_cipher=ciphers.Cipher(ciphers.algorithms.AES(encryption_key),
                                                      ciphers.modes.CTR(iv),
                                                      self._backend),
                         iv=iv)

  def test_AuthenticationCorrectness(self):

    signing_key = self.fernet._signing_key

    data = byteblock(0)

    auth = cmac.CMAC(ciphers.algorithms.AES(signing_key), backend=default_backend())
    auth.update(data)
    hazmat_tag = auth.finalize()

    fernet_tag = self.fernet._cmac(data)

    assert hazmat_tag == fernet_tag

    for l in xrange(1, 207):
      data = os.urandom(l)

      auth = cmac.CMAC(ciphers.algorithms.AES(signing_key), backend=default_backend())
      auth.update(data)
      hazmat_tag = auth.finalize()

      fernet_tag = self.fernet._cmac(data)

      assert hazmat_tag == fernet_tag

  def test_DecryptionCorrectness(self):

    encryption_key = self.fernet._encryption_key
    signing_key = self.fernet._signing_key

    iv = os.urandom(16)
    ptx = "this is a super secret message"
    timestamp = struct.pack(">Q", int(time.time()))

    cipher = ciphers.Cipher(ciphers.algorithms.AES(encryption_key),
                            ciphers.modes.CTR(iv),
                            self._backend)

    encryptor = cipher.encryptor()
    ctx = encryptor.update(ptx) + encryptor.finalize()

    auth = cmac.CMAC(ciphers.algorithms.AES(signing_key), backend=default_backend())
    auth.update(b"\x91" + timestamp + iv + ctx)
    mac = auth.finalize()

    # Assemble a ciphertext using token created by `cryptography`. Ensure Fermet
    # 0x91 can decrypt the ciphertext correctly.
    mocked_result = base64.urlsafe_b64encode(b"\x91" + timestamp + iv + ctx + mac)

    fernet_result = self.fernet.encrypt(ptx, iv)

    assert mocked_result == fernet_result
    assert self.fernet.decrypt(mocked_result) == ptx


if __name__ == "__main__":
  # Helpers
  test_num()
  test_byteblock()

  # Crypto
  a = TestFernet()
  # Errors
  a.test_InvalidVersionToken()
  a.test_ShortCipherText()
  a.test_InvalidMac()
  a.test_ExpiredTimeStamp()
  a.test_EmptyMessage()
  # Functionality & Correctness:
  a.test_Functionality()
  a.test_EncryptionCorrectness()
  a.test_AuthenticationCorrectness()
  a.test_DecryptionCorrectness()
