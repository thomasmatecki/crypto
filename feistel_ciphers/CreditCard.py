import Feistel


class CreditCardFeistel(Feistel):
    """
      Inspired by:  https://blog.cryptographyengineering.com
                    /2011/11/10/format-preserving-encryption-or-how-to/

      Uses an unbalanced feistel network on 7 bytes. L and R
      are thus not the same length, they are 3 and 4 bytes
      respectfully in the result.

            | 0 | 1 | 2 | 3 |------| 4 | 5 | 6 |
                     ______\________/   /   /
                    /   ____\__________/   /
                   /   /   __\____________/
                  /   /   /   \_____
                 /   /   /          \
                /   /   /  PRF(| i | 3 | 4 | 5 | 6 |)
               /   /   /   xor | 0 | 1 | 2 | 3 |
            | 4 | 5 | 6 |------| - | - | - | - |

    """

    def _feistel_round_enc(self, round_index, data):
        """This function implements one round of Fiestel decryption block.
        """
        round_pad = self._prf(self._round_keys[round_index], chr(round_index) + bytes(data[:3]))

        return bytearray(ord(r) ^ d for r, d in zip(round_pad, data[3:])) + data[:3]

    def _feistel_round_dec(self, round_index, data):
        """This function implements one round of Fiestel
           encryption block on 7 bytes.
        """
        round_pad = self._prf(self._round_keys[round_index], chr(round_index) + bytes(data[4:]))

        # L{i + 1} = Ri, R{i + 1} = Li xor FK(i, Ri).
        return data[4:] + bytearray(ord(r) ^ d for r, d in zip(round_pad, data[:4]))

    def num_to_bytes(self, num):
        return bytearray(map(lambda i: (num >> i * 8) & 0xff, range(7)))

    def bytes_to_num(self, bytes):
        num = 0x00
        for i, b in enumerate(bytes):
            num = num | (b << 8 * i)
        return num

    def encrypt(self, data):
        """
        Equipped with a 7 byte feistel network, we can now encrypt a 7 byte
        string(i.e. 56 bits). A 56 bit number may be larger than a credit
        card (max 10^16). Thus simply repeat encryption until a value less
        than 10^16 is produced. This should happen with probability:
                (10^16 / 2^56) = 0.13877
        ... so relatively often, which is nice.

        Note repeated application produces a series of ciphertexts:

        ctx = enc( ... enc(enc(ptx))) => ctx1, ctx2, ..., ctx

        ... where only ptx and ctx are less than 10^16.
        """
        assert data <= MAX_CC_NUM

        plain_bytes = self.num_to_bytes(data)

        cipher_num = MAX_CC_NUM + 1

        while cipher_num > MAX_CC_NUM:
            cipher_num = self.bytes_to_num(
                reduce(lambda d, i: self._feistel_round_enc(i, d),
                       range(self._num_rounds),
                       plain_bytes))

            plain_bytes = self.num_to_bytes(cipher_num)

        return cipher_num

    def decrypt(self, ctx):
        """
        Decrypt in the same manner as encryption. The algorithm should
        terminate as soon as number that is less than 10^16 produced.
        """

        assert ctx <= MAX_CC_NUM

        cipher_bytes = self.num_to_bytes(ctx)

        plain_num = MAX_CC_NUM + 1

        while plain_num > MAX_CC_NUM:
            plain_num = self.bytes_to_num(
                reduce(lambda d, i: self._feistel_round_dec(i, d),
                       range(self._num_rounds),
                       cipher_bytes))
            cipher_bytes = self.num_to_bytes(plain_num)

        return plain_num
