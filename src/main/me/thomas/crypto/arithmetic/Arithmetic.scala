package me.thomas.crypto.arithmetic

import scala.util.Random

trait Arithmetic {
  /**
    * Given two numbers a and b, calculates the gcd(a,b)
    *
    * @param a
    * @param b
    */
  def euclid(a: BigInt, b: BigInt): BigInt = {
    val r = a % b
    if (r == 0) b
    else euclid(b, r)
  }

  /**
    * Given two numbers such that a >= b, computes x, y such that
    * ax + by = gcd(a,b)
    *
    * @param a
    * @param b
    * @return
    */
  def extendedEuclid(a: BigInt, b: BigInt): (BigInt, BigInt) =
    if (a % b == 0) (0, 1)
    else {
      val (x, y) = extendedEuclid(b, a % b)
      (y, x - y * (a / b))
    }

  case class MultModulo(N: BigInt) extends Sampling {

    if (N < 2)
      throw new Error(s"Invalid N=$N for multiplicative group Modulo N")

    /**
      *
      * @return
      */
    def sample(): BigInt = from[BigInt] {
      if (N == 1) 1 else BigInt(2 * N.bitLength, Random) % N
    } ensure { s =>
      s > 0 && euclid(N, s) == 1
    }
  }

}
