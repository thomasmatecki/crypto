package me.thomas.crypto

import scala.util.Random

/**
  * Toolset for repeated or conditional sampling
  */
trait Sampling {
  /**
    * Shim for repeated sampling. Repeatedly
    * invokes `sampler` until `cond` is `true`
    * then returns the result.
    *
    * For @example:
    * {{{
    *   from {
    *     BigInt(numBits, Random)
    *   } ensure (b => b > 1 && millerRabin(b))
    * }}}
    * ...is equivalent to the loop...
    * {{{
    *    var x: BigInt = 0
    *    do {
    *      x = BigInt(numBits, Random)
    *    } while (x < 2 || !millerRabin(x))
    *    x
    * }}}
    * ... but does not leak a mutable {{{var x}}}
    *
    * @param sampler
    * @tparam T
    * @return
    */
  def from[T](sampler: => T): {
    def ensure(cond: T => Boolean): T
  } = new {
    def ensure(cond: T => Boolean): T = {
      val s: T = sampler

      if (cond(s)) s
      else ensure(cond)
    }
  }

  /**
    * Execute something some side-affecting block of code an
    * `n` times.
    *
    * For @example:
    *
    * {{{
    *  100 times {
    *      val p = randomSafe(8)
    *
    *      assert(millerRabin(p))
    *      assert(millerRabin((p - 1) / 2))
    *      assert(p.bitLength <= 8)
    *    }
    *
    * }}}
    *
    * @param n
    * @return
    */
  implicit def intWithTimes(n: Int): {
    def times(f: => Unit): Unit
  } = new {
    def times(f: => Unit): Unit = 1 to n foreach { _ => f }
  }


}


object Sampling {
  def bigInt(numBits: Int): BigInt = BigInt(numBits, Random).setBit(numBits - 1)

}