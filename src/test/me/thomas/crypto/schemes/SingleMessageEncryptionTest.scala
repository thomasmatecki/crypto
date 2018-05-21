package me.thomas.crypto.schemes

import junit.framework.TestCase

import scala.util.Random


class SingleMessageEncryptionTest extends TestCase {

  implicit val prg: PseudoRandomGenerator = new RSAMidHalfPRG {}


  def testEncDecNum(): Unit = {

    val key = BigInt(32, Random)
    val crypter = new SingleMessageEncrypter(key)
    val message = BigInt(200, Random).toByteArray

    val cipherText = crypter.enc(message)
    val result = crypter.dec(cipherText)

    assert(message.deep == result.deep)
  }


  def testEncDecString(): Unit = {

    val secretString = "the quick brown fox jumped over the lazy dog"
    val key = Sampling.bigInt(32)
    val crypter = new SingleMessageEncrypter(key)
    val cipher = crypter.enc(secretString.getBytes())
    val decrypted = crypter.dec(cipher)
    val decryptedString = new String(decrypted)

    assert(decryptedString.equals(secretString))

  }

  def testTenMBEncrytion(): Unit = {

    val key = Sampling.bigInt(1024)

    val testInput = (1 to 9999999).map(_.toByte).toArray

    val crypter = new SingleMessageEncrypter(key)

    val start = System.currentTimeMillis
    val cipher = crypter.enc(testInput)
    val encDoneTime = System.currentTimeMillis - start
    val decrypted = crypter.dec(cipher)
    val decDoneTime = System.currentTimeMillis - start

    System.out.println(s"Encryption done in $encDoneTime ms")
    System.out.println(s"Decryption done in $decDoneTime ms")

    assert(decrypted.deep == testInput.deep)
  }

  def testSlowTenMBEncryption(): Unit = {


    val slowPRG = new RSAMidBitPRG(32)
    val key = BigInt(1024, Random)

    val crypter = new SingleMessageEncrypter(key)(prg = slowPRG)


    val testInput = (1 to 99999).map(_.toByte).toArray

    val start = System.currentTimeMillis
    val cipher = crypter.enc(testInput)
    val encDoneTime = System.currentTimeMillis - start
    val decrypted = crypter.dec(cipher)

    System.out.println(s"One Bit Extending PRG Encryption done in $encDoneTime ms")

    assert(decrypted.deep == testInput.deep)

  }
}
