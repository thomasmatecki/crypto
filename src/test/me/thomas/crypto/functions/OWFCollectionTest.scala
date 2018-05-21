package me.thomas.crypto.functions

import junit.framework.TestCase

/**
  *
  */
class OWFCollectionTest extends TestCase with Sampling {


  def testDiscreteLog(): Unit = {
    val dl4: OneWayFunction[BigInt, BigInt] = DiscreteLogOneWay.gen(4)

    100 times {
      val x = dl4.sample()
      assert(x.bitLength <= 4)
    }
  }

  def testRSACollection(): Unit = {

    val rsa4 = RSAOneWay.gen(4)

    100 times {
      val x = rsa4.sample()
    }
  }

  /**
    *
    */
  def testRSATrapDoor(): Unit = {

    100 times {

      val (rsa4, t) = RSATrapDoor.gen(16)

      val x0 = rsa4.sample()
      val y = rsa4.eval(x0)
      val x1 = rsa4.invert(y, t)

      assert(x0.equals(x1))

    }
  }

  /**
    *
    */
  def testRSALongKey(): Unit = {

    val (rsa4, t) = RSATrapDoor.gen(1024)

    val x0 = rsa4.sample()
    val y = rsa4.eval(x0)
    val x1 = rsa4.invert(y, t)

    assert(x0.equals(x1))


  }


}
