package me.thomas.crypto.functions



/**
  *
  */
trait PseudoRandomFunction extends ((BigInt) => BigInt) with PseudoRandomGenerator {

  val seed: BigInt


  def outputLength: Int = seed.bitLength * 2

  //def root: BigInt = generate(seed, seed.bitLength)

  /**
    * Tree-like PRF; Given a seed, invoke a length doubling generator. Then, based
    * on the leading bit of the index, recursively expand either the left or right
    * half. Continue bit-shifting the index until the leftmost bit is reached(i.e.
    * all bits of the index are exhausted).
    *
    * @param index
    * @param prgInput
    * @return
    */
  private def getIndex(index: BigInt, prgInput: BigInt): BigInt = {

    if (index.bitLength == 0)
      prgInput

    else {

      val expanded = generate(prgInput, outputLength)
      // Take first half or last half of Input based on least
      // significant bit of index.
      val nextHalf = if (index.testBit(0)) expanded >> seed.bitLength // The left half
      else expanded & (BigInt(2).pow(seed.bitLength) - 1) // The right half
      getIndex(index >> 1, nextHalf)
    }
  }

  override def apply(index: BigInt): BigInt = getIndex(index, generate(seed, seed.bitLength))

}
