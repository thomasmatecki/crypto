from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.backends import default_backend
#
from cryptography.hazmat.primitives.ciphers import Cipher, modes
from cryptography.hazmat.primitives.ciphers.algorithms import AES
import base64
import binascii


def xor(a, b):
  """
  xors two raw byte streams.
  """
  assert len(a) == len(b), "Lengths of two strings are not same. a = {}, b = {}".format(len(a), len(b))
  return ''.join(chr(ord(ai) ^ ord(bi)) for ai, bi in zip(a, b))


class Feistel:
  """
  For 1, 2, or 3 rounds of Feistel the cipher does provide security because the
  resulting cipher does not behave like a random permutation.

  For a message L || R, the result of 1, 2, and 3 feistel rounds is below:
  0) L                         || R
  1) R                         || F(1, R) xor L
  2) L xor F(1, R)             || F(2, L xor F(1, R)) xor R
  3) R xor F(2, L xor F(1, R)) || F(3, F(2, L xor F(1, R))) xor L xor F(1, R)

  - For 1 round of Feistel, the ciphertext reveals the left half of the message. An
    active attacker can thus query the the cipher with message {000...} || R0 and the
    result will be:

          R || {000...} xor F(1, R) = R || F(1, R)

    ...so the output of the first round function is revealed and decryption is trivial.

  - For 2 rounds of Feistel, the ciphertext is:

          L xor F(1, R) || F(2, L xor F(1, R)) xor R

    An attacker can query the cipher with a message message L || R0 = {000...} || FOO and
    the result will be:

          F(1, FOO) || F(2, {000...}  xor F(1, FOO)) xor FOO

    ...revealing the value of F(1, FOO). Then repeatedly querying with messages Li || FOO
    results in :

          Li xor F(1, FOO) || F(2, Li xor F(1, FOO)) xor FOO

    ... and the attacker can then xor the left half, Li xor F(1, FOO) with F(1, FOO)
    resulting in Li, thus allowing them to distinguish the cipher from a random permutation.
    Note this can be done with any choice of L, not necessarily just {000...}.

  - For 3 feistel rounds, one can distinguish from a random permutation by repeatedly
    sampling the cipher, with distinct inputs. Let Lc || Rc denote the cipher text of some
    input L || R, and let L' = Lc xor R. Then, for a random permutation, after n samples,
    the probability of a collision of L', based on the birthday bound is, approximately:

          n^2 / 2 ^25

    Whereas for the 3 round feistel, a collision of F(2, L xor F(1, R)) occurs whenever:
    either of: 
      - A collision of F(2, *), which occurs with probability n^2 / 2 ^25
      - A collision Li xor F(1, Ri), with occurs with probability n^2 / 2 ^25

    ... so the probability of collision is roughly twice as likely as for a PRP, and thus
    through repeated sampling an attacker can distinguish it from one.
  """

  def __init__(self, key, num_rounds, backend=None):
    if backend is None:
      backend = default_backend()

    key = base64.urlsafe_b64decode(key)
    if len(key) != 16:
      raise ValueError(
        "Key must be 16 url-safe base64-encoded bytes. Got: {} ({})".format(key, len(key))
      )
    self._num_rounds = num_rounds
    self._encryption_key = key
    self._backend = backend
    self._round_keys = [self._encryption_key \
                        for _ in xrange(self._num_rounds)]
    for i in xrange(self._num_rounds):
      if i == 0: continue
      self._round_keys[i] = self._SHA256hash(self._round_keys[i - 1])

  def _SHA256hash(self, data):
    h = hashes.Hash(hashes.SHA256(), self._backend)
    h.update(data)
    return h.finalize()

  def encrypt(self, data):
    assert len(data) % 2 == 0, "Supports only balanced feistel at " \
                               "this moment. So provide even length messages."

    return reduce(lambda d, i: self._feistel_round_enc(i, d),
                  range(self._num_rounds),
                  bytearray(data))

  def decrypt(self, ctx):
    assert len(ctx) % 2 == 0, "Supports only balanced feistel at " \
                              "this moment. So provide even length ciphertext."

    return reduce(lambda d, i: self._feistel_round_dec(i - 1, d),
                  range(self._num_rounds, 0, -1),
                  bytearray(ctx))

  def _prf(self, key, data):
    """Set up secure round function F
    """
    # The AES cipher - doesn't seem to care about key length
    cipher = Cipher(AES(key), modes.CBC('\0' * 16), backend=self._backend)

    # Pad with x\00 to a multiple 128 bits
    padding = (16 - len(data) % 16) * '\0'

    encryptor = cipher.encryptor()

    data = encryptor.update(padding + data) + encryptor.finalize()

    return data

  def _feistel_round_enc(self, round_index, data):
    """This function implements one round of Fiestel decryption block.
    """
    mid = len(data) / 2
    round_pad = self._prf(self._round_keys[round_index], chr(round_index) + bytes(data[:mid]))

    return bytearray(ord(r) ^ d for r, d in zip(round_pad, data[mid:])) + data[:mid]

  def _feistel_round_dec(self, round_index, data):
    """This function implements one round of Fiestel encryption block.
    """
    mid = len(data) / 2
    # Prefix the R with the round index and call AES PRF
    round_pad = self._prf(self._round_keys[round_index], chr(round_index) + bytes(data[mid:]))

    # L{i + 1} = Ri, R{i + 1} = Li xor FK(i, Ri).
    return data[mid:] + bytearray(ord(r) ^ d for r, d in zip(round_pad, data[:mid]))


class LengthPreservingCipher(object):
  # 'length' is in bytes here
  def __init__(self, key, length=6):
    self._length = length
    self._feistel = MyFeistel(key, 10, )

  def encrypt(self, data):
    assert len(data) == self._length
    return self._feistel.encrypt(data)

  def decrypt(self, data):
    assert len(data) == self._length
    return self._feistel.decrypt(data)


MAX_CC_NUM = (10 ** 16) - 1

