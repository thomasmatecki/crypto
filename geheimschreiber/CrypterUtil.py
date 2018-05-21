"""
Thomas Matecki
CS 5830 - Gehemschreiber - Part 2
"""
from bitstring import BitArray, Bits
from functools import reduce


def make_rotor_file(rotor_bits, filename):
  rotor_file = open(filename, "w")

  for i, k in enumerate(sorted(rotor_bits, key=lambda rb: len(rb))):
    rotor_file.write("Rotor %d: %s" % (i, k.bin))
    rotor_file.write("\n")

  rotor_file.close()


def make_key_file(rotor_lengths, filename):
  """

  :return:
  """
  len_idx = {x: i for i, x in enumerate(sorted(rotor_lengths))}

  ordering = reduce(lambda s, i: (" %d" % i) + s,
                    [len_idx[i] for i in reversed(rotor_lengths)], "\n")

  key_file = open(filename, "w")
  key_file.write("Order:%s" % ordering)
  key_file.write("Offset: 0 0 0 0 0 0 0 0 0 0 0\n")


class GBits(BitArray):

  def get(self, key):
    return self._datastore.getbit(key)

  def swap(self, a, b):
    """
    """
    tmp = self[a]
    self[a] = self[b]
    self[b] = tmp


class Crypter:
  # Use the given alphabet to convert the clear-text to a number between
  # 0 and 31

  crypt = []

  BIT_RANGE = list(map(lambda b: GBits(uint=b, length=5), range(0, 32)))
  PLAINTEXT_ALPHABET = "2T3O4HNM5LRGIPCVEZDBSYFXAWJ6UQK7"
  CRYPTO_ALPHABET = {letter: GBits(uint=i, length=5) for (i, letter) in enumerate(PLAINTEXT_ALPHABET)}

  def swaps(self, input_bits, swap_bits):

    swapped_letter = input_bits.copy()
    if swap_bits[0]: swapped_letter.swap(0, 4)  # If b5 is 1 interchange c0 and c4
    if swap_bits[1]: swapped_letter.swap(0, 1)  # If b6 is 1 interchange c0 and c1
    if swap_bits[2]: swapped_letter.swap(1, 2)  # If b7 is 1 interchange c1 and c2
    if swap_bits[3]: swapped_letter.swap(2, 3)  # If b8 is 1 interchange c2 and c3
    if swap_bits[4]: swapped_letter.swap(3, 4)  # If b9 is 1 interchange c3 and c4

    return swapped_letter

  @staticmethod
  def sieve(iterbitset, rotor_lengths, count, iw_fr, iw_to):
    """

    :return:
    """
    for fr, ks in enumerate(iterbitset):

      if len(ks) == 1:
        k = next(iter(ks))
        for i in range(iw_fr, iw_to):
          for j in range(fr % rotor_lengths[i], len(iterbitset), rotor_lengths[i]):
            i_b = i - iw_fr
            count -= len(iterbitset[j])
            ki_b = k[i_b]
            iterbitset[j] = [jk for jk in iterbitset[j] if jk[i_b] == ki_b]
            count += len(iterbitset[j])

            if len(iterbitset[j]) == 0:  # short circuit!
              raise ValueError('Invalid Key!')

      if count <= len(iterbitset):
        break

    return count

  def check(self, xor_ks, swap_ks, debug=False):
    """
    :param debug:
    :return:
    """
    for xks, sks, (m, c) in zip(xor_ks, swap_ks, self.crypt):
      xk = xks[0]
      sk = sks[0]

      c0 = self.swaps(m ^ xk, sk)

      if c != c0:
        return False

      if debug == True:
        print("%s; %s : (%s, %s) : %s; %s  : %s; %s" %
              (self.PLAINTEXT_ALPHABET[m.uint],
               m,
               xk,
               sk,
               self.PLAINTEXT_ALPHABET[c0.uint],
               c0,
               self.PLAINTEXT_ALPHABET[c.uint],
               c))

    return True

  def generate_rotor_bits(self, rotor_lengths, xor_ks, swap_ks):
    b = [BitArray() for i in range(10)]

    for (i, xks, sks) in zip(range(0, max(rotor_lengths)), xor_ks, swap_ks):
      b[0] += BitArray(bool=xks[0][0])
      b[1] += BitArray(bool=xks[0][1])
      b[2] += BitArray(bool=xks[0][2])
      b[3] += BitArray(bool=xks[0][3])
      b[4] += BitArray(bool=xks[0][4])
      b[5] += BitArray(bool=sks[0][0])
      b[6] += BitArray(bool=sks[0][1])
      b[7] += BitArray(bool=sks[0][2])
      b[8] += BitArray(bool=sks[0][3])
      b[9] += BitArray(bool=sks[0][4])

    for (i, bi) in enumerate(b):
      b[i] = bi[0:rotor_lengths[i]]

    return b
