from CrypterUtil import Crypter
from collections import defaultdict
from bitstring import Bits
from GWriter import GeheimSchreiber
from CrypterUtil import make_rotor_file, make_key_file
from itertools import permutations


class UMUMVEVECracker(Crypter):
  SWAP_PREIMAGE = defaultdict(set)
  SWAP_PARTIAL_INV = defaultdict(set)
  xor_ks = []
  xk_lc = 0  # Log-cardinality of xor-keyspace

  crypt = []

  def __init__(self):
    """
    The Encryption Alg. is Two Steps:
    """
    for input_bits in self.BIT_RANGE:
      for swap_bits in self.BIT_RANGE:
        swapped_letter = self.swaps(input_bits, swap_bits)

        self.SWAP_PARTIAL_INV[(input_bits.uint, swapped_letter.uint)].add(Bits(uint=swap_bits.uint,
                                                                               length=5))

        self.SWAP_PREIMAGE[swapped_letter.uint].add(Bits(uint=input_bits.uint,
                                                         length=5))

  def load(self, ciphertext):

    for cletter, pletter in zip(ciphertext[0:11], "UMUM4VEVE35"):
      cipher_letter = self.CRYPTO_ALPHABET[cletter].copy()
      message_letter = self.CRYPTO_ALPHABET[pletter].copy()

      swap_inputs = self.SWAP_PREIMAGE[cipher_letter.uint]
      self.xor_ks.append([message_letter ^ swap_input for swap_input in swap_inputs])
      self.xk_lc += len(self.xor_ks[-1])

      self.crypt.append(([message_letter], cipher_letter))

    for cletter in ciphertext[11:-2]:
      self.xor_ks.append(self.BIT_RANGE.copy())
      self.xk_lc += len(self.xor_ks[-1])

      cipher_letter = self.CRYPTO_ALPHABET[cletter].copy()
      self.crypt.append((self.BIT_RANGE.copy(), cipher_letter))

    for cletter, pletter in zip(ciphertext[-2:], "35"):
      cipher_letter = self.CRYPTO_ALPHABET[cletter].copy()
      message_letter = self.CRYPTO_ALPHABET[pletter].copy()

      swap_inputs = self.SWAP_PREIMAGE[cipher_letter.uint]
      self.xor_ks.append([message_letter ^ swap_input for swap_input in swap_inputs])
      self.xk_lc += len(self.xor_ks[-1])

      self.crypt.append(([message_letter], cipher_letter))

    return

  def try_sieve(self, xor_rotors, xor_ks_c):
    """
    :param self:
    :return:
    """

    try:
      self.sieve(xor_ks_c, xor_rotors, self.xk_lc, 0, 5)
      print("XOR Key Sieve Succeeded...")
      return xor_rotors

    except ValueError as ve:
      return None

  def crack(self):

    rotors = {47, 53, 59, 61, 64, 65, 67, 69, 71, 73}

    for xor_rotors in permutations(rotors, 5):
      xor_ks_c = self.xor_ks.copy()

      if self.try_sieve(xor_rotors, xor_ks_c) != None:
        print("success: %s " % (xor_rotors,))

        swap_ks = []
        sk_lc = 0  # Log-cardinality of swap-keyspace

        for xks, (ms, c) in zip(xor_ks_c, self.crypt):
          ks_ms = [m ^ ks for m in ms for ks in xks]
          swap_bits = set()

          for ks_m in ks_ms:
            swap_bits = swap_bits | self.SWAP_PARTIAL_INV[(ks_m.uint, c.uint)]

          swap_ks.append(swap_bits)
          sk_lc += len(swap_bits)

        for swap_rotors in permutations(rotors - set(xor_rotors)):

          try:
            swap_ks_c = swap_ks.copy()

            while sk_lc > len(swap_ks):
              sk_lc = self.sieve(swap_ks_c, xor_rotors[0:5] + swap_rotors, sk_lc, 5, 10)

            print("SWAP Key Sieve Succeeded...")

            print("Rotors 5 through 9: %s" % (swap_rotors,))

            rotor_lengths = list(xor_rotors[0:5] + swap_rotors)

            print(rotor_lengths)

            rotor_bits = self.generate_rotor_bits(rotor_lengths, xor_ks_c, swap_ks_c)

            make_rotor_file(rotor_bits, "./config/rotors_4.txt")

            make_key_file(rotor_lengths, "./config/key_4.txt")

          except ValueError as ve:
            continue

        break


def main():
  """

  :return:
  """

  cracker = UMUMVEVECracker()

  ciphertext_file = open("./config/ciphertext_4.txt")

  for cline in ciphertext_file:
    cracker.load(cline.strip())

  cracker.crack()

  g_writer = GeheimSchreiber("./config/rotors_4.txt", "./config/key_4.txt")
  ciphertext_file = open("./config/ciphertext_4.txt")

  for line in ciphertext_file:
    plaintext = g_writer.decrypt(line.strip())
    print(plaintext)


if __name__ == '__main__':
  main()
