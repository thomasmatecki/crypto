package me.thomas.crypto.arithmetic

object BigSafePrime extends App with Primes {


  override def main(args: Array[String]): Unit = {

    val x = randomSafe(500)
    println(x)
  }
}
