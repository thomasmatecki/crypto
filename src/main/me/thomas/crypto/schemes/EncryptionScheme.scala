package me.thomas.crypto.schemes

/**
  * Encryption Scheme
  *
  * @tparam D
  * @tparam C
  */
trait EncryptionScheme[D, C] {

  val seed: BigInt

  def enc(m: D): C

  def dec(c: C): D

}

/**
  * Mix-in Byte-Array One-Time-Pad
  */
trait OneTimePad {
  def xor(a: Array[Byte], b: Array[Byte]): Array[Byte] = a.zip(b).map { case (i, j) => (i ^ j).toByte }
}

/**
  * Single Message Encryption Schema on Arrays of Bytes.
  *
  * @param seed
  * @param prg
  */
class SingleMessageEncrypter(val seed: BigInt)(implicit val prg: PseudoRandomGenerator)
  extends EncryptionScheme[Array[Byte], Array[Byte]]
    with OneTimePad {

  override def enc(m: Array[Byte]): Array[Byte] = {
    val gK = prg.generate(seed, (m.length - 1) * 8).toByteArray
    xor(gK, m)
  }

  override def dec(c: Array[Byte]): Array[Byte] = {
    val gK = prg.generate(seed, (c.length - 1) * 8).toByteArray
    xor(gK, c)
  }
}

/**
  * Multi-message Encryption Schema on Arrays of Bytes.
  *
  * @param seed
  * @param prf
  */
class MultiMessageEncrypter(val seed: BigInt, indexLength: Int = 32)(implicit val prf: PseudoRandomFunction)
  extends EncryptionScheme[Array[Byte], (BigInt, Array[Byte])]
    with OneTimePad {

  override def enc(m: Array[Byte]): (BigInt, Array[Byte]) = {
    val r = Sampling.bigInt(indexLength)
    (r, xor(m, prf(r).toByteArray))
  }

  override def dec(rc: (BigInt, Array[Byte])): Array[Byte] = xor(prf(rc._1).toByteArray, rc._2)

}