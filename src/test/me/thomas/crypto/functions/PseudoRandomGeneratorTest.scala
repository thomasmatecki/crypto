package me.thomas.crypto.functions

import junit.framework.TestCase

import scala.util.Random

/**
  *
  */
class PseudoRandomGeneratorTest extends TestCase with RSAMidHalfPRG {


  def testRSAPRG(): Unit = {

    val seed = BigInt(32, Random)
    val result = generate(seed, 200)

    assert(result.bitLength == 200)

  }


  def testRSAPRGConsistent(): Unit = {

    //val RSA32BitPRG = new RSAPRG(512)

    val seed = BigInt(32, Random)

    val result0 = generate(seed, 2000)
    val result1 = generate(seed, 2000)

    assert(result0 == result1)

  }

}