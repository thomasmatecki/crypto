package me.thomas.crypto

import scala.io.Source

object medallionCracker extends App {

  val fileLocation = sys.env("FILE_LOCATION")

  val inputHashes: Set[String] = Source.fromFile(fileLocation).getLines.toSet

  val alphabet = Range('A', 'Z', 1).map(_.toChar)
  val digits = Range(0, 9, 1)


  val medallions = for {
    l1 <- alphabet
    l2 <- alphabet
    l3 <- alphabet
    d1 <- digits
    d2 <- digits
    d3 <- digits
  } yield s"$l1$l2$l3$d1$d2$d3"

  medallions.par.foreach(m => {

    val hash = HashAlgorithms.sha256(m.getBytes).foldLeft(new String)((s, i) => s + f"$i%02x")

    if (inputHashes contains hash) {
      print(s"medallion: $m -> hash: $hash \n")
    }

  })
}