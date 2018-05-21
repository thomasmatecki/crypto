from feistel_ciphers.Feistel import Feistel, LengthPreservingCipher, CreditCardFeistel
import pytest
import base64
import os
import random as r


class TestMyFeistel:

  def test_feistel_round_enc(self):
    key = base64.urlsafe_b64encode(os.urandom(16))
    feistel = MyFeistel(key, 1)
    msg = bytearray('secret')
    result = feistel._feistel_round_enc(0, msg)

    assert result[3:] == msg[:3]

  def test_feistel_round_enc_dec(self):
    key = base64.urlsafe_b64encode(os.urandom(16))
    feistel = MyFeistel(key, 1)
    msg = bytearray('secret')
    half_cipher = feistel._feistel_round_enc(0, msg)
    result = feistel._feistel_round_dec(0, half_cipher)
    assert result == msg

  def test_encrypt(self):
    key = base64.urlsafe_b64encode(os.urandom(16))

    feistel = MyFeistel(key, 10)

    for i in range(20):
      ctx = bytes(feistel.encrypt(os.urandom(i * 2)))
      assert len(ctx) == 2 * i

    ctxs = set()

    for j in xrange(255):
      ctx = bytes(feistel.encrypt(os.urandom(4)))
      assert ctx not in ctxs
      ctxs.add(ctx)

  def test_decrypt(self):
    key = base64.urlsafe_b64encode(os.urandom(16))

    feistel = MyFeistel(key, 10)

    for i in range(20):
      ctx = bytes(feistel.encrypt(os.urandom(i * 2)))
      assert len(ctx) == 2 * i

  def test_encrypt_decrypt(self):
    key = base64.urlsafe_b64encode(os.urandom(16))
    feistel = MyFeistel(key, 3)
    msg = "secret"
    cipher_text = feistel.encrypt(msg)
    assert len(cipher_text) == len(msg)
    result = feistel.decrypt(cipher_text)
    assert result == msg

  def test_prf(self):
    key = base64.urlsafe_b64encode(os.urandom(16))

    feistel = MyFeistel(key, 3)
    data = os.urandom(6)

    prvs = set()

    # The PRF is indeed a _function_
    for _ in xrange(20):
      assert feistel._prf(key, data) == feistel._prf(key, data)

    # There should be no 1 byte collisions (with extremely
    # high probability)
    for data in map(lambda i: bytearray([i]), range(255)):
      prv = feistel._prf(key, bytes(data))
      assert prv not in set()
      assert len(prv) == 16  # The output length is 128 bits

      prvs.add(prv)

  def test_Functionality(self):
    key = base64.urlsafe_b64encode(os.urandom(16))
    feistel = MyFeistel(key, 10)

    # decrypt(encrypt(msg)) == msg
    for i in xrange(20):
      msg = os.urandom(6)
      ctx = feistel.encrypt(msg)
      assert len(ctx) == len(msg)
      assert feistel.decrypt(ctx) == msg

  def test_OddLengthMessage(self):
    key = base64.urlsafe_b64encode(os.urandom(16))

    feistel = MyFeistel(key, 1)

    msg = os.urandom(3)

    with pytest.raises(AssertionError):
      result = feistel.encrypt(msg)


class TestLengthPreservingCipher:
  def test_Functionality(self):
    key = base64.urlsafe_b64encode(os.urandom(16))
    lpc = LengthPreservingCipher(key, )

    # decrypt(encrypt(msg)) == msg
    for i in xrange(20):
      msg = os.urandom(6)
      assert lpc.decrypt(lpc.encrypt(msg)) == msg

  def test_LengthPreservation(self):
    key = base64.urlsafe_b64encode(os.urandom(16))
    lpc = LengthPreservingCipher(key, )

    # decrypt(encrypt(msg)) == msg
    for i in xrange(20):
      msg = os.urandom(6)
      ctx = lpc.encrypt(msg)

      assert len(ctx) == len(msg) == 6
      assert lpc.decrypt(ctx) == msg

  def test_WrongMessageLength(self):
    key = base64.urlsafe_b64encode(os.urandom(16))
    lpc = LengthPreservingCipher(key, 6)
    msg = os.urandom(7)

    with pytest.raises(AssertionError):
      lpc.encrypt(msg)

    with pytest.raises(AssertionError):
      lpc.decrypt(msg)

  def test_EmptyMessage(self):
    # A message longer than 128 bits
    key = base64.urlsafe_b64encode(os.urandom(16))
    lpc = LengthPreservingCipher(key, 0)
    ctx = lpc.encrypt("")
    assert len(ctx) == 0
    assert lpc.decrypt(ctx) == ""

  def test_MessageLengths(self):
    # A message longer than 128 bits
    key = base64.urlsafe_b64encode(os.urandom(16))
    lpc = LengthPreservingCipher(key, 18)

    for i in xrange(0, 10):
      lpc = LengthPreservingCipher(key, i * 2)
      msg = os.urandom(i * 2)
      ctx = lpc.encrypt(msg)

      assert len(ctx) == len(msg)
      assert lpc.decrypt(ctx) == msg


class TestCreditCardFeistel:

  def test_feistel_round_enc(self):
    key = base64.urlsafe_b64encode(os.urandom(16))
    feistel = CreditCardFeistel(key, 1)

    msg = bytearray('secrets')

    result = feistel._feistel_round_enc(0, msg)
    assert len(result) == 7
    result[4:] == msg[:3]

  def test_feistel_round_enc_dec(self):
    key = base64.urlsafe_b64encode(os.urandom(16))
    feistel = CreditCardFeistel(key, 1)

    msg = bytearray('secrets')

    result = feistel._feistel_round_enc(0, msg)

    result = feistel._feistel_round_dec(0, result)

    assert result == msg

  def test_encrypt(self):
    key = base64.urlsafe_b64encode(os.urandom(16))

    feistel = CreditCardFeistel(key, 10)

    result = feistel.encrypt(1234234598774572)

    assert len(str(result)) <= 16

  def test_decrypt(self):
    key = base64.urlsafe_b64encode(os.urandom(16))

    feistel = CreditCardFeistel(key, 1)

    for _ in xrange(20):
      plain_num = r.randint(0,10**16)

      cipher_num = feistel.encrypt(plain_num)

      assert feistel.decrypt(cipher_num) == plain_num
