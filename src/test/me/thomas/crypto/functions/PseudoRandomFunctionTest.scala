package me.thomas.crypto.functions

import junit.framework.TestCase

import scala.util.Random

class PseudoRandomFunctionTest extends TestCase with Sampling {

  def testRSAPRF(): Unit = {


    val rsaPRF = new PseudoRandomFunction with RSAMidHalfPRG {
      override val seed: BigInt = Sampling.bigInt(512)
    }

    val r0 = rsaPRF(3)
    val r1 = rsaPRF(3)

    assert(r0 == r1)


    2 times {

      val input = BigInt(32, Random)
      assert(
        rsaPRF(input) == rsaPRF(input)
      )

    }
  }
}
