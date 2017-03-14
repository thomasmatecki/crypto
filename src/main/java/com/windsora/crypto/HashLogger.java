package com.windsora.crypto;

public class HashLogger {
    public static void print512Bits(byte[] bytes) {

        assert bytes.length == 64;

        System.out.println('|' + new String(new char[77]).replace('\0', '-') + '|');

        System.out.printf("| %5d bytes", bytes.length);

        System.out.println(new String(new char[59]).replace('\0', ' ') + '|');

        System.out.println('|' + new String(new char[77]).replace('\0', '-') + '|');

        for (int i = 0; i < 8; i++) {

            int bitFr = i * 8;
            int bitTo = bitFr + 8;

            //System.out.print("|" + bitFr + "|" + bitTo + "|");

            System.out.printf("|%5d| %5d|", bitFr, bitTo);

            for (int k = bitFr; k < bitTo; k++) {

                String s1 = String.format("%8s", Integer.toBinaryString(bytes[k] & 0xFF)).replace(' ', '0');
                System.out.print(s1);
            }

            System.out.println('|');

        }
    }

}