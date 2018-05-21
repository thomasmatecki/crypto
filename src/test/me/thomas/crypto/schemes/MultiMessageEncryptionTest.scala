package me.thomas.crypto.schemes

import junit.framework.TestCase

class MultiMessageEncryptionTest extends TestCase {

  implicit val prf: PseudoRandomFunction = new PseudoRandomFunction with RSAMidHalfPRG {
    override val seed: BigInt = Sampling.bigInt(512)

  }

  def testEncDecString(): Unit = {

    val secretString = "the quick brown fox jumped over the lazy dog"
    val seed = Sampling.bigInt(32)

    val crypter = new MultiMessageEncrypter(seed)
    val cipher = crypter.enc(secretString.getBytes())
    val decrypted = crypter.dec(cipher)
    val decryptedString = new String(decrypted)

    assert(decryptedString.equals(secretString))

  }


}
