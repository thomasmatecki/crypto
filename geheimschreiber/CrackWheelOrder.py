from WheelBitCracker import WheelBitCracker
from CrypterUtil import make_rotor_file, make_key_file
import itertools as it
from GWriter import GeheimSchreiber


def crack():
  cracker = WheelBitCracker()

  ciphertext_file = open("./ciphertexts/ciphertext_3.txt")
  plaintext_file = open("./plaintexts/plaintext_3.txt")

  for pline, cline in zip(plaintext_file, ciphertext_file):
    cracker.load(pline.strip(), cline.strip())

  xor_ks, xk_lc = cracker.xor_key_combs()

  rotors = {47, 53, 59, 61, 64, 65, 67, 69, 71, 73}

  for xor_rotors in it.permutations(rotors, 5):

    try:
      xor_ks_c = xor_ks.copy()
      cracker.sieve(xor_ks_c, xor_rotors, xk_lc, 0, 5)

      print("XOR Key Sieve Succeeded...")
      print("Rotors 0 though 4: %s" % (xor_rotors,))

      swap_ks, sk_lc = cracker.swap_key_combs(xor_ks_c)

      for swap_rotors in it.permutations(rotors - set(xor_rotors)):

        try:

          swap_ks_c = swap_ks.copy()

          cracker.sieve(swap_ks_c, xor_rotors[0:5] + swap_rotors, sk_lc, 5, 10)
          print("SWAP Key Sieve Succeeded...")

          print("Rotors 5 through 9: %s" % (swap_rotors,))

          assert cracker.check(xor_ks_c, swap_ks_c)

          rotor_lengths = list(xor_rotors[0:5] + swap_rotors)

          rotor_bits = cracker.generate_rotor_bits(rotor_lengths, xor_ks_c, swap_ks_c)

          make_rotor_file(rotor_bits, "./config/rotors_3.txt")

          make_key_file(rotor_lengths, "./config/key_3.txt")

          break
        except ValueError as ve:
          continue

      break
    except ValueError as ve:
      continue


def main():
  crack()

  g_writer = GeheimSchreiber("./config/rotors_3.txt", "./config/key_3.txt")

  plaintext_file = open("./config/plaintext_3.txt")

  for line in plaintext_file:
    ciphertext = g_writer.encrypt(line.strip())
    print(ciphertext)


if __name__ == '__main__':
  main()
