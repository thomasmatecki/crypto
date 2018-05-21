from bitstring import Bits
from CrypterUtil import Crypter
import re


class GeheimSchreiber(Crypter):
  rotors = []

  debug_flag = False

  def __init__(self, rotor_file, key_file, **kwargs):
    """
    :param rotor_file:
    """
    rotor_bits = self.load_rotors(rotor_file)
    order, self.initial_positions = self.load_key(key_file)

    # A fixed permutation of the rotors is chosen
    self.rotors = tuple(rotor_bits[int(i)] for i in map(int, order))

    self.reset_rotors()

  def load_rotors(self, filename):
    return [Bits(bin=re.search("Rotor \d: (\d+)", line).group(1))
            for line in open(filename).readlines()]

  def load_key(self, filename):
    key = open(filename).readlines()
    return (re.search("Order:((\s\d)+)", key[0]).group(1).split(),
            tuple(map(int, re.search("Offset:((\s\d+)+)", key[1]).group(1).split())))

  def rotor_val(self, i):
    return self.rotors[i][self.positions[i] % len(self.rotors[i])]

  def advance_rotors(self):
    """
    :return:
    """
    self.positions = [position + 1 for position in self.positions]

  def read_rotors(self):
    """
    The rotors are little-endian:
    [b0 b1 b2 b3 b4...] -> 01001 = 18
      1  2  4  8 16

    Whereas the bitstring is big-endian
     b4 b3 b2 b1 b0 -> 10010 = 18
     16  8  4  2  1
    :return:
    """
    return Bits(length=5,
                uint=sum(
                  v << i
                  for i, v
                  in enumerate(self.rotor_val(i)
                               for i in range(4, -1, -1))))

  def reset_rotors(self):
    self.positions = self.initial_positions

  def encrypt(self, message):
    """
    :param message:
    :return:
    """

    result = ""

    for letter in message:
      # For i = 0 . . . 4, ci = ci ⊕ bi (take xor).

      crypto_letter = self.CRYPTO_ALPHABET[letter]

      b0_4 = self.read_rotors()

      debug = "%s : %s; %s" % (letter, crypto_letter, b0_4)

      crypto_letter = crypto_letter ^ b0_4

      debug = "%s; %s" % (debug, crypto_letter)

      if self.rotor_val(5):
        crypto_letter.swap(0, 4)  # If b5 is 1 interchange c0 and c4
      if self.rotor_val(6):
        crypto_letter.swap(0, 1)  # If b6 is 1 interchange c0 and c1
      if self.rotor_val(7):
        crypto_letter.swap(1, 2)  # If b7 is 1 interchange c1 and c2
      if self.rotor_val(8):
        crypto_letter.swap(2, 3)  # If b8 is 1 interchange c2 and c3
      if self.rotor_val(9):
        crypto_letter.swap(3, 4)  # If b9 is 1 interchange c3 and c4

      result += self.PLAINTEXT_ALPHABET[crypto_letter.uint]

      debug = "%s; %s : %s" % (debug, crypto_letter, result[-1])

      if self.debug_flag:
        print(debug)

      # Before the next character is encrypted, each rotor is stepped one step.
      self.advance_rotors()

    return result

  def decrypt(self, ciphertext):
    """
    :param ciphertext:
    :return:
    """
    result = ""

    for letter in ciphertext:
      crypto_letter = self.CRYPTO_ALPHABET[letter].copy()

      debug = "%s : %s" % (crypto_letter, letter)

      if self.rotor_val(9):
        crypto_letter.swap(3, 4)  # If b9 is 1 interchange c3 and c4
      if self.rotor_val(8):
        crypto_letter.swap(2, 3)  # If b8 is 1 interchange c2 and c3
      if self.rotor_val(7):
        crypto_letter.swap(1, 2)  # If b7 is 1 interchange c1 and c2
      if self.rotor_val(6):
        crypto_letter.swap(0, 1)  # If b6 is 1 interchange c0 and c1
      if self.rotor_val(5):
        crypto_letter.swap(0, 4)  # If b5 is 1 interchange c0 and c4

      debug = "%s; %s" % (crypto_letter, debug)

      b0_4 = self.read_rotors()

      crypto_letter = (crypto_letter ^ b0_4)

      debug = "%s; %s; %s" % (crypto_letter, b0_4, debug)

      result += self.PLAINTEXT_ALPHABET[crypto_letter.uint]

      debug = "%s : %s" % (result[-1], debug)

      if self.debug_flag:
        print(debug)

      self.advance_rotors()

    return result


def main():
  g_writer = GeheimSchreiber("./config/rotors_1.txt", "./config/key_1.txt")

  ciphertext_file = open("./config/ciphertext_1.txt")

  for line in ciphertext_file:
    plaintext = g_writer.decrypt(line.strip())
    print(plaintext)


if __name__ == '__main__':
  main()
