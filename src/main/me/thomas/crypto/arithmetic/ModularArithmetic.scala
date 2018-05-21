package me.thomas.crypto.arithmetic



trait ModularArithmetic extends Arithmetic {

  val N: BigInt

  /**
    * calculates a raised to x
    *
    * @param a0 a
    * @param x0 the exponent
    * @return
    */
  def exp(a0: BigInt, x0: BigInt): BigInt = {
    var r: BigInt = 1
    var x = x0
    var a = a0

    while (x > 0) {
      r = if (x % 2 == 1) (r * a) % N else r
      x = x / 2
      a = (a * a) % N
    }
    r
  }

  /**
    * Find element gcd(a,N) = 1 (mod `modulo`)
    *
    * @param a
    * @return
    */
  def inverse(a: BigInt): BigInt = {
    val (x, _) = extendedEuclid(a, N)
    (x + N) % N // Ensure positive
  }
}
