from GWriter import GeheimSchreiber
from bitstring import Bits, BitArray
from collections import defaultdict
from CrypterUtil import Crypter, GBits, make_rotor_file


class WheelBitCracker(Crypter):
  """
  """

  SWAP_PREIMAGE = defaultdict(set)
  SWAP_PARTIAL_INV = defaultdict(set)
  crypt = []

  def __init__(self):
    """
    The Encryption Alg. is Two Steps:
      1) XOR bits from rotors 0-4,
      2) Perform bit swaps based on

    For a an input character, determine the characters that the swap portion of the
    encryption can result in. Build a map from Encryption output to the preimage of
    the swap step
    """
    for input_bits in self.BIT_RANGE:
      for swap_bits in self.BIT_RANGE:
        swapped_letter = self.swaps(input_bits, swap_bits)

        self.SWAP_PARTIAL_INV[(input_bits.uint, swapped_letter.uint)].add(Bits(uint=swap_bits.uint,
                                                                               length=5))

        self.SWAP_PREIMAGE[swapped_letter.uint].add(Bits(uint=input_bits.uint,
                                                         length=5))

  def load(self, message, ciphertext):

    if len(message) != len(ciphertext):
      raise ValueError('The message and ciphertext must be the same length')

    for mletter, cletter in zip(message, ciphertext):
      cipher_letter = self.CRYPTO_ALPHABET[cletter].copy()
      message_letter = self.CRYPTO_ALPHABET[mletter].copy()

      self.crypt.append((message_letter, cipher_letter))

  def xor_key_combs(self):
    """

    :return:
    """
    xor_ks = []
    xk_lc = 0  # Log-cardinality of xor-keyspace

    for message_letter, cipher_letter in self.crypt:
      swap_inputs = self.SWAP_PREIMAGE[cipher_letter.uint]
      xor_ks.append([message_letter ^ swap_input for swap_input in swap_inputs])
      xk_lc += len(xor_ks[-1])

    return xor_ks, xk_lc

  def swap_key_combs(self, xor_ks):
    """

    :param xor_ks:
    :return:
    """
    swap_ks = []
    sk_lc = 0  # Log-cardinality of swap-keyspace

    for xks, (m, c) in zip(xor_ks, self.crypt):
      ks_m = next(iter(xks)) ^ m
      swap_bits = self.SWAP_PARTIAL_INV[(ks_m.uint, c.uint)]
      swap_ks.append(swap_bits)
      sk_lc += len(swap_bits)

    return swap_ks, sk_lc


  def crack_bits(self, rotor_lengths, check=False):
    """
    :return:
    """

    xor_ks, xk_lc = self.xor_key_combs()

    self.sieve(xor_ks, rotor_lengths, xk_lc, 0, 5)

    swap_ks, sk_lc = self.swap_key_combs(xor_ks)

    self.sieve(swap_ks, rotor_lengths, sk_lc, 5, 10)

    return self.generate_rotor_bits(rotor_lengths, xor_ks, swap_ks)


def main():
  cracker = WheelBitCracker()

  ciphertext_file = open("./gwriter/part_2/ciphertext.txt")
  plaintext_file = open("./gwriter/part_2/plaintext.txt")

  for pline, cline in zip(plaintext_file, ciphertext_file):
    cracker.load(pline.strip(), cline.strip())

  rotor_bits = cracker.crack_bits([47, 53, 59, 61, 64, 65, 67, 69, 71, 73], check=True)

  make_rotor_file(rotor_bits, "./gwriter/part_2/rotors.txt")

  g_writer = GeheimSchreiber("./gwriter/part_2/rotors.txt", "./gwriter/part_2/key.txt")

  plaintext_file = open("./gwriter/part_2/plaintext.txt")

  for line in plaintext_file:
    ciphertext = g_writer.encrypt(line.strip())
    print(ciphertext)

  return


if __name__ == '__main__':
  main()
