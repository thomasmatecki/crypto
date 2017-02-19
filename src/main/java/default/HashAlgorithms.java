import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.nio.ByteBuffer;
import java.math.BigInteger;

public class HashAlgorithms {

  public static void main(String[] args) {

    sha256("The Quick Brown Fox Jumbed over the lazy dog! Whille the cat watched and the dog remained asleep.");

  }

  public static void sha256(String input) {

    /* Hash Values;  First 32 Bits of the fractional parts of the square roots of the first 8 primes */
    final int[] H = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };

    /* Round Constants; First 32 bits of the cube roots of the first 64 primes*/
    final int[] K = { 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1,
        0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d,
        0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3,
        0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb,
        0xbef9a3f7, 0xc67178f2 };

    /**
     * Pre-processing:
     * append the bit '1' to the message
     * append n bits '0', where n is the minimum number >= 0 such that the resulting message length (modulo 512 in bits) is 448.
     * append length of message (without the '1' bit or padding), in bits, as 64-bit big-endian integer (this will make the entire post-processed length a multiple of 512 bits)
     */

    byte[] inputBytes = input.getBytes();

    int padLength = Math.abs((448 - (inputBytes.length + 1) * java.lang.Byte.SIZE % 512)) / java.lang.Byte.SIZE;

    int bufferSize = inputBytes.length + 1 + padLength + (Long.SIZE / Byte.SIZE);

    System.out.println(
        "The input message is size: " + inputBytes.length * Byte.SIZE + " bits; " + inputBytes.length + " bytes");

    byte[] paddedMsg = ByteBuffer.allocate(bufferSize).put(inputBytes).put(Byte.MIN_VALUE)
        .putLong(padLength + inputBytes.length + 1, inputBytes.length * Byte.SIZE).array();

    System.out.println("The padded message is " + paddedMsg.length + " bytes");

    for (int chnk = 0; chnk < paddedMsg.length; chnk += 64) {

      int[] w = new int[64];

      /**
       * System.out.println("-------------------------------------------------------------------");
       * System.out.println("| BLOCK: " + chnk);
       * System.out.println("-------------------------------------------------------------------");
      */

      for (int i = 0; i < 16; i++) {
        /** 
         * 0 0 ... 3
         * 1 4 ... 7
         * 2 8 ... 11
         * .
         * .
         * .
         * 15 60 ... 63
         */
        int pf = chnk + i * 4;
        int pt = pf + 3;

        byte[] t = Arrays.copyOfRange(paddedMsg, pf, pt + 1);

        System.out.print(
            "POS: " + i + "; FROM: " + pf + "; TO: " + pt + " VAL: " + java.nio.ByteBuffer.wrap(t).getInt() + ";");

        for (byte t0 : t) {
          System.out.print(" " + t0);
        }

        w[i] = java.nio.ByteBuffer.wrap(t).getInt();

        System.out.println();

      }

      /** for i from 16 to 63
       *    s0 := (w[i-15] rightrotate 7) xor (w[i-15] rightrotate 18) xor (w[i-15] rightshift 3)
       *    s1 := (w[i-2] rightrotate 17) xor (w[i-2] rightrotate 19) xor (w[i-2] rightshift 10)
       *    w[i] := w[i-16] + s0 + w[i-7] + s1 */
      for (int i = 16; i <= 63; i++) {

        int s0 = Integer.rotateRight(w[i - 15], 7) //
            ^ Integer.rotateRight(w[i - 15], 18) //
            ^ Integer.rotateRight(w[i - 15], 3); //

        int s1 = Integer.rotateRight(w[i - 2], 17) //
            ^ Integer.rotateRight(w[i - 2], 19) //
            ^ Integer.rotateRight(w[i - 2], 10); //

        w[i] = w[i - 16] + s0 + w[i - 7] + s1;

      }

      // Initialize working variables to current hash value:
      int a = H[0];
      int b = H[1];
      int c = H[2];
      int d = H[3];
      int e = H[4];
      int f = H[5];
      int g = H[6];
      int h = H[7];

      // Compression function main loop:
      for (int i = 0; i <= 63; i++) {
        /**
         *       S1 := (e rightrotate 6) xor (e rightrotate 11) xor (e rightrotate 25)
         *       ch := (e and f) xor ((not e) and g)
         *       temp1 := h + S1 + ch + k[i] + w[i]
         *       S0 := (a rightrotate 2) xor (a rightrotate 13) xor (a rightrotate 22)
         *       maj := (a and b) xor (a and c) xor (b and c)
         *       temp2 := S0 + maj
         *        
         *       h := g
         *       g := f
         *       f := e
         *       e := d + temp1
         *       d := c
         *       c := b
         *       b := a
         *       a := temp1 + temp2
         */

        int s1 = Integer.rotateRight(e, 6) //
            ^ Integer.rotateRight(e, 11) //
            ^ Integer.rotateRight(e, 25); //

        int ch = (e & f) ^ (~e & g);

//int tmp1 = 

      }

    }
  }

}