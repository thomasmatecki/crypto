package me.thomas.crypto.functions

/**
  *
  *
  */
trait PseudoRandomGenerator {

  val owp: OneWayFunction[BigInt, BigInt]

  val predicate: (BigInt => BigInt)

  def generate(seed: BigInt, outputLength: Int): BigInt
}


trait Predicates {

  def middleBits(input: BigInt): BigInt = {

    val len = input.bitLength
    val output = input >> (len / 4) & BigInt(2).pow(len / 2) - 1

    output
  }

  def midBit(input: BigInt): BigInt = BigInt(
    if (input.testBit(input.bitLength / 2)) 1 else 0
  )
}

/**
  *
  *
  */
trait RSAMidHalfPRG extends PseudoRandomGenerator with Predicates {
  val rsaBits: Int = 512
  override val owp: OneWayFunction[BigInt, BigInt] = RSAOneWay.gen(rsaBits)
  override val predicate: BigInt => BigInt = middleBits

  override def generate(seed: BigInt, outputLength: Int): BigInt = {

    val extLen = seed.bitLength / 2
    var result: BigInt = BigInt(1)
    var next = seed

    while (result.bitLength < outputLength) {
      next = owp.eval(next)
      result = (result << extLen) | predicate(next)
    }

    // Make output exactly `bitlength` bits
    result >> (result.bitLength - outputLength)
  }
}

/**
  *
  * @param rsaBits
  */
class RSAMidBitPRG(rsaBits: Int) extends PseudoRandomGenerator with Predicates {

  override val owp: OneWayFunction[BigInt, BigInt] = RSAOneWay.gen(rsaBits)

  override val predicate: BigInt => BigInt = midBit

  override def generate(seed: BigInt, outputLength: Int): BigInt = {

    var result: BigInt = BigInt(1)
    var next = seed

    while (result.bitLength < outputLength) {
      next = owp.eval(next)
      result = (result << 1) | predicate(next)
    }

    result
  }

}