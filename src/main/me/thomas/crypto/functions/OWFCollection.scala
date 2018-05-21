package me.thomas.crypto.functions

import me.thomas.crypto.arithmetic.ModularArithmetic

import scala.util.Random


trait OneWayFunction[D, R] extends ((D) => R) {
  /**
    * Sample a value from the Domain
    *
    * @return
    */
  def sample(): D

  /**
    * Evaluate the one-way function for input `x`
    *
    * @param x
    * @return
    */
  def eval(x: D): R

  def apply(x: D): R = eval(x)
}

trait TrapDoor[T, R] {
  /**
    * Given Trapdoor information, invert the function
    *
    * @param y The output of the one-way function to be inverted
    * @param t the trapdooor information
    * @return
    */
  def invert(y: R, t: T): T
}

trait FunctionCollection[I, F] {
  //def apply(numBits: I): F = gen(numBits)

  def gen(numBits: I): F
}

/**
  * A collection of one way functions
  *
  * @tparam I The function sample parameters domain
  * @tparam D The input sample domain type
  * @tparam R The return domain type. If D = R, this is a one
  *           way permutation(sort-of).
  */
trait OWFCollection[I, D, R]
  extends FunctionCollection[I, OneWayFunction[D, R]] {
  def gen(numBits: I): OneWayFunction[D, R]
}

/**
  * A one-way function with a trapdoor.
  *
  * @tparam I
  * @tparam D
  * @tparam R
  * @tparam T
  */
trait TrapDoorCollection[I, D, R, T]
  extends FunctionCollection[I, (OneWayFunction[D, R] with TrapDoor[T, R], T)] {
  def gen(numBits: I): (OneWayFunction[D, R] with TrapDoor[T, R], T)
}

/**
  *
  */
object DiscreteLogOneWay extends OWFCollection[Int, BigInt, BigInt] {

  override def gen(numBits: Int): OneWayFunction[BigInt, BigInt] =
    new OneWayFunction[BigInt, BigInt] with Primes with ModularArithmetic {

      val (q, g) = genGroup(numBits)
      val N: BigInt = q

      override def sample(): BigInt = BigInt(numBits, Random) % q

      override def eval(x: BigInt): BigInt = exp(g, x)
    }
}

/**
  *
  */
trait RSAOneWay extends OWFCollection[Int, BigInt, BigInt] {

  override def gen(numBits: Int): OneWayFunction[BigInt, BigInt] =

    new OneWayFunction[BigInt, BigInt] with Primes with ModularArithmetic {

      val (p, q) = (random(numBits), random(numBits))
      val N: BigInt = p * q
      // N = pq and p, q are primes, and therefore Φ(N) = (p − 1)(q − 1)
      val phiN = if (p == q) p - 1 else (p - 1) * (q - 1)
      val e: BigInt = MultModulo(phiN).sample()

      override def sample(): BigInt = MultModulo(N).sample()

      override def eval(x: BigInt): BigInt = exp(x, e)
    }
}

object RSAOneWay {
  def gen(numBits: Int): OneWayFunction[BigInt, BigInt] = new RSAOneWay {}.gen(numBits)
}

object RSATrapDoor
  extends TrapDoorCollection[Int, BigInt, BigInt, BigInt]
    with Primes
    with Arithmetic {

  override def gen(numBits: Int): (OneWayFunction[BigInt, BigInt] with TrapDoor[BigInt, BigInt], BigInt) = {

    val (p, q) = (random(numBits), random(numBits))

    // Calculate the Euler Totient function Φ(N); the number of primes less
    // that N that are co-prime to N. For me.thomas.crypto.arithmetic.Primes and p,q with p*q = N:
    //    - If p != q Then: Φ(N) = (p − 1)(q − 1)
    //    - If p = q  Then: Φ(N) = (p − 1)
    val phiN = if (p == q) p - 1 else (p - 1) * (q - 1)
    val e: BigInt = MultModulo(phiN).sample()

    val mod = new ModularArithmetic {
      override val N: BigInt = phiN
    }

    val owf = new OneWayFunction[BigInt, BigInt]
      with TrapDoor[BigInt, BigInt]
      with ModularArithmetic {

      val N: BigInt = p * q

      override def sample(): BigInt = MultModulo(N).sample()

      override def eval(x: BigInt): BigInt = exp(x, e)

      override def invert(y: BigInt, t: BigInt): BigInt = exp(y, t)
    }

    // Trapdoor function & Trapdoor Information.
    (owf, mod.inverse(e))
  }
}