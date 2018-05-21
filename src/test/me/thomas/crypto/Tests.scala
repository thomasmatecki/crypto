package me.thomas.crypto

import junit.framework.TestCase
import me.thomas.crypto.arithmetic.{ModularArithmetic, Primes}

class Tests extends TestCase with Primes with Sampling {

  val arith = new ModularArithmetic {
    override val N: BigInt = 5
  }


  def testExtendedEuclid(): Unit = {

    val a = 28
    val b = 21
    val gcd = arith.euclid(a, b)

    val (x, y) = arith.extendedEuclid(a, b)

    assert(
      (a * x) + (b * y) == gcd && gcd == 7)

  }

  def testInverse(): Unit = {
    val i = arith.inverse(4)
    assert((4 * i) % arith.N == 1)
  }


  def testMillerRabin(): Unit = {

    3 until 1000 foreach {
      i =>
        if (millerRabin(i)) assert {
          2 until Math.sqrt(i).toInt forall { j => i % j != 0 }
        } else {
          2 until Math.sqrt(i).toInt exists { j => i % j == 0 }
        }
    }

    assert(!millerRabin(9))
    assert(!millerRabin(561))
    assert(!millerRabin(4))
    assert(!millerRabin(6))
    assert(!millerRabin(21))
    assert(!millerRabin(1080))
    assert(!millerRabin(95))
    assert(!millerRabin(63))
    assert(!millerRabin(21))
    assert(!millerRabin(51))

    assert(millerRabin(2))
    assert(millerRabin(7))
    assert(millerRabin(53))
    assert(millerRabin(29))
    assert(millerRabin(23))
    assert(millerRabin(13))
    assert(millerRabin(11))

  }

  def testRandomPrime() {

    val p = random(8)

  }

  def testSafeRandomPrime() {

    100 times {
      val p = randomSafe(8)

      assert(millerRabin(p))
      assert(millerRabin((p - 1) / 2))
      assert(p.bitLength <= 8)
    }

  }

  /**
    * [2] Crypto.stanford.edu. (2018). Number Theory - Generators. [online]
    * Available at: https://crypto.stanford.edu/pbc/notes/numbertheory/gen.html
    */
  def testGenGroup(): Unit = {

    val (p, g) = genGroup(4)
    /*
    There are only three 4 bit multiplicative groups of integers modulo
    a prime number; p = 7 and p = 11.
    */
    assert(p == 7 || p == 11 || p == 5)

    val mod = new ModularArithmetic {
      override val N: BigInt = p
    }

    val g0: BigInt = 1

    // p is a safe prime, so nothing in [1, p) divides p
    val gI = g0 until p

    // Generate the units of the the group by exponentiation.
    val generated = g0 until p map {
      mod.exp(g, _)
    }

    assert(
      generated.foldRight(gI.toSet) { (i: BigInt, s: Set[BigInt]) => s - i } isEmpty
    )
  }
}
