package com.windsora.cryto;

import java.nio.ByteBuffer;

public class HashAlgorithms {
  /* Round Constants; First 32 bits of the cube roots of the first 64 primes*/
  static final int[] K = { 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
      0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
      0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152,
      0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138,
      0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70,
      0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
      0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa,
      0xa4506ceb, 0xbef9a3f7, 0xc67178f2 };

  public static void main(String[] args) {

    sha256(
        "The Quick Brown Fox Jumbed over the lazy dog! While the cat watched and the dog remained asleep.".getBytes());
    sha256("".getBytes());

  }

  public static void sha256(byte[] inputBytes) {

    /* Initial Hash Values;  First 32 Bits of the fractional parts of the square roots of the first 8 primes */
    int[] hash = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };

    /** Pre-processing: Append three things to the input: a single 1 bit, some number(L) of 
     * 0 bits, and 64 bits(representing a Big-Endian Integer) containing the message length(in 
     * bits) appended. The number of 0 bits(L) is the is the the smallest number that will make
     * result in a length that can be split into 64 bit chunks(i.e. K + 1 + L + 64 % 512 == 0, 
     * where K is the length of the input message). Note, this takes as input an array of bytes 
     * and all operations are on bytes not bits. */

    int padLength = Math.abs((448 - (inputBytes.length + 1) * Byte.SIZE % 512)) / Byte.SIZE;

    int bufferSize = inputBytes.length + 1 + padLength + (Long.SIZE / Byte.SIZE);

    // Allocate the message buffer and put the input message into it.
    ByteBuffer msgBuffer = ByteBuffer.allocate(bufferSize).put(inputBytes);

    // Append the byte '1000000' to the message
    msgBuffer.put(Byte.MIN_VALUE);

    /** Append length of message (without the '1' bit or padding), in bits, as 64-bit big-endian 
     *  integer (this will make the entire post-processed length a multiple of 512 bits)  */
    msgBuffer.putLong(padLength + inputBytes.length + 1, inputBytes.length * Byte.SIZE);

    for (int chnk = 0; chnk < bufferSize; chnk += 64) {

      /**  Create a 64-entry message schedule array w[0..63] of 32-bit words and 
       *   copy chunk into first 16 words w[0..15] of the message schedule array. */
      int[] w = new int[64];

      for (int i = 0; i < 16; i++) {
        w[i] = msgBuffer.getInt(chnk + i * 4);
      }

      /**  Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array:
       *   for i from 16 to 63
       *     s0 := (w[i-15] rightrotate 7) xor (w[i-15] rightrotate 18) xor (w[i-15] rightshift 3)
       *     s1 := (w[i-2] rightrotate 17) xor (w[i-2] rightrotate 19) xor (w[i-2] rightshift 10)
       *     w[i] := w[i-16] + s0 + w[i-7] + s1 */
      for (int i = 16; i < 64; i++) {

        int s0 = Integer.rotateRight(w[i - 15], 7) //
            ^ Integer.rotateRight(w[i - 15], 18) //
            ^ (w[i - 15] >>> 3); //

        int s1 = Integer.rotateRight(w[i - 2], 17) //
            ^ Integer.rotateRight(w[i - 2], 19) //
            ^ (w[i - 2] >>> 10); //

        w[i] = w[i - 16] + s0 + w[i - 7] + s1;

      }

      // Initialize 8 working variable and fill with the current hash value:
      int a = hash[0];
      int b = hash[1];
      int c = hash[2];
      int d = hash[3];
      int e = hash[4];
      int f = hash[5];
      int g = hash[6];
      int h = hash[7];

      // Compression function main loop:
      for (int i = 0; i < 64; i++) {

        int s1 = Integer.rotateRight(e, 6) //       S1 := (e rightrotate 6) xor (e rightrotate 11) xor (e rightrotate 25)
            ^ Integer.rotateRight(e, 11) //
            ^ Integer.rotateRight(e, 25); //

        int ch = (e & f) ^ ((~e) & g); //           ch := (e and f) xor ((not e) and g)
        int tmp1 = h + s1 + ch + K[i] + w[i];//     temp1 := h + S1 + ch + k[i] + w[i]

        int s0 = Integer.rotateRight(a, 2) //       S0 := (a rightrotate 2) xor (a rightrotate 13) xor (a rightrotate 22)
            ^ Integer.rotateRight(a, 13) //         
            ^ Integer.rotateRight(a, 22); //        

        int maj = (a & b) ^ (a & c) ^ (b & c);//    maj := (a and b) xor (a and c) xor (b and c)
        int tmp2 = s0 + maj; //                     temp2 := S0 + maj

        h = g;
        g = f;
        f = e;
        e = d + tmp1;
        d = c;
        c = b;
        b = a;
        a = tmp1 + tmp2;
      }

      hash[0] = a + hash[0];
      hash[1] = b + hash[1];
      hash[2] = c + hash[2];
      hash[3] = d + hash[3];
      hash[4] = e + hash[4];
      hash[5] = f + hash[5];
      hash[6] = g + hash[6];
      hash[7] = h + hash[7];

    } // chnk

    for (int h0 : hash) {
      System.out.print(Integer.toHexString(h0) + " ");
    }

    System.out.println();
  }

}