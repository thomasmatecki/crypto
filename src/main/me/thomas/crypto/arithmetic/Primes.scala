package me.thomas.crypto.arithmetic

import me.thomas.crypto.Sampling

import scala.util.Random

trait Primes extends Sampling {
  /**
    * @param n the number to check for primality
    * @param t the number of trials to execute
    * @return
    */
  def millerRabin(n: BigInt)(implicit t: Int = 3): Boolean = {

    val mod = new ModularArithmetic {
      val N: BigInt = n
    }

    var q = n - 1
    var k = 0
    while (q % 2 == 0) {
      q /= 2
      k += 1
    }

    /**
      * [1] D. Knuth, "Factoring and Primes" in The Art of Computer Programming;
      * Volume 2: Semi-numerical algorithms. Addison-Wesley, 1998, pp. 395.
      *
      * @param y
      * @param j
      * @return
      */
    @scala.annotation.tailrec
    def repSquare(y: BigInt, j: BigInt): Boolean = {
      if (y == n - 1 || (y == 1 && j == 0)) return true
      if (y == 1 && j > 0) return false
      if (j < k - 1) repSquare(y * y % n, j + 1)
      else false
    }

    (0 to t) forall (_ => {

      val a = from {
        BigInt(n.bitLength, Random) % n
      } ensure (_ > 0)

      lazy val t1 = mod.exp(a, n - 1) == 1
      lazy val t2 = repSquare(mod.exp(a, q), 0)
      if (n < 2) false else t1 && t2
    })
  }

  def random(numBits: Int): BigInt = from {
    BigInt(numBits, Random)
  } ensure (b => b > 1 && millerRabin(b))


  /**
    * Generates a random N-Bit 'safe' prime
    *
    * @param numBits
    * @return
    */
  def randomSafe(numBits: Int): BigInt = from {
    (2 * random(numBits - 1)) + 1
  } ensure millerRabin


  /**
    * Picks a random n-bit 'safe' prime p and a
    * generator g for the multiplicative group
    * modulo p.
    *
    * @param numBits
    * @return
    */
  def genGroup(numBits: Int): (BigInt, BigInt) = {

    val p: BigInt = randomSafe(numBits)
    val q: BigInt = (p - 1) / 2
    val g0: BigInt = 2
    val G = g0 until p

    val mod = new ModularArithmetic {
      val N: BigInt = p
    }

    for (g: BigInt <- G) {
      if (mod.exp(g, q) != 1) return (p, g)
    }
    throw new Error("Invalid Safe Prime")
  }
}
