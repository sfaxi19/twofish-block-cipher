import com.sun.org.apache.xpath.internal.SourceTree;
import exceptions.WhiteningException;

import java.io.*;
import java.net.SocketPermission;
import java.nio.ByteBuffer;
import java.util.Random;

/**
 * Created by sfaxi19 on 30.10.16.
 */
public class Twofish {

    private int k = 4;
    private int[] sboxKeys;
    public int[] subKeys;
    private static final int ROUNDS = 16;
    private static final int IN_WHITENING = 0;
    private static final int OUT_WHITENING = 4;
    private static final int RS_PRIMITIVE = 0x14D;
    private static final int MDS_PRIMITIVE = 0x169;
    private static final int ENCRYPTION_MOD = 0;
    private static final int DECRYPTION_MOD = 15;
    private static final byte[] RS_MATRIX = {
            (byte) 0x01, (byte) 0xA4, (byte) 0x55, (byte) 0x87, (byte) 0x5A, (byte) 0x58, (byte) 0xDB, (byte) 0x9E,
            (byte) 0xA4, (byte) 0x56, (byte) 0x82, (byte) 0xF3, (byte) 0x1E, (byte) 0xC6, (byte) 0x68, (byte) 0xE5,
            (byte) 0x02, (byte) 0xA1, (byte) 0xFC, (byte) 0xC1, (byte) 0x47, (byte) 0xAE, (byte) 0x3D, (byte) 0x19,
            (byte) 0xA4, (byte) 0x55, (byte) 0x87, (byte) 0x5A, (byte) 0x58, (byte) 0xDB, (byte) 0x9E, (byte) 0x03};
    private static final byte[] MDS_MATRIX = {
            (byte) 0x01, (byte) 0xEF, (byte) 0x5B, (byte) 0x5B,
            (byte) 0x5B, (byte) 0xEF, (byte) 0xEF, (byte) 0x01,
            (byte) 0xEF, (byte) 0x5B, (byte) 0x01, (byte) 0xEF,
            (byte) 0xEF, (byte) 0x01, (byte) 0xEF, (byte) 0x5B
    };
    private static final byte[][] TQ0 = {
            {0x08, 0x01, 0x07, 0x0D, 0x06, 0x0F, 0x03, 0x02, 0x00, 0x0B, 0x05, 0x09, 0x0E, 0x0C, 0x0A, 0x04},
            {0x0E, 0x0C, 0x0B, 0x08, 0x01, 0x02, 0x03, 0x05, 0x0F, 0x04, 0x0A, 0x06, 0x07, 0x00, 0x09, 0x0D},
            {0x0B, 0x0A, 0x05, 0x0E, 0x06, 0x0D, 0x09, 0x00, 0x0C, 0x08, 0x0F, 0x03, 0x02, 0x04, 0x07, 0x01},
            {0x0D, 0x07, 0x0F, 0x04, 0x01, 0x02, 0x06, 0x0E, 0x09, 0x0B, 0x03, 0x00, 0x08, 0x05, 0x0C, 0x0A}};

    private static final byte[][] TQ1 = {
            {0x02, 0x08, 0x0B, 0x0D, 0x0F, 0x07, 0x06, 0x0E, 0x03, 0x01, 0x09, 0x04, 0x00, 0x0A, 0x0C, 0x05},
            {0x01, 0x0E, 0x02, 0x0B, 0x04, 0x0C, 0x03, 0x07, 0x06, 0x0D, 0x0A, 0x05, 0x0F, 0x09, 0x00, 0x08},
            {0x04, 0x0C, 0x07, 0x05, 0x01, 0x06, 0x09, 0x0A, 0x00, 0x0E, 0x0D, 0x08, 0x02, 0x0B, 0x03, 0x0F},
            {0x0B, 0x09, 0x05, 0x01, 0x0C, 0x03, 0x0D, 0x0E, 0x06, 0x04, 0x07, 0x0F, 0x02, 0x00, 0x08, 0x0A}};

    private static final int POL = 0x01010101;
    private int correlation = 0;
    private int zeros = 0;
    private int ones = 0;

    public Twofish() {
    }

    public static void main(String... args) throws IOException {
        Twofish t = new Twofish();
        if (args.length >= 4) {
            if (args[0].equals("--enc")) {
                if (args[3].equals("-k")) {
                    t.encryption(args[1], args[2], t.getKeyFromHexString(args[4]));
                }
                if (args[3].equals("-p")) {
                    t.encryption(args[1], args[2], t.getKeyFromPassword(args[4]));
                }
                if (args[3].equals("-g")) {
                    t.encryption(args[1], args[2], t.generationKey());
                }
                System.out.println("Encryption complite!");
            }
            if (args[0].equals("--dec")) {
                if (args[3].equals("-k")) {
                    t.decryption(args[1], args[2], t.getKeyFromHexString(args[4]));
                }
                if (args[3].equals("-p")) {
                    t.decryption(args[1], args[2], t.getKeyFromPassword(args[4]));
                }
                System.out.println("Decryption complite!");
            }
        } else {
            System.out.println("You can use next position:\n" +
                    "- Twofish --enc [input filepath] [output filepath] [-p]:[-k]:[-g] [key] - for encryption input file and save him to output filepath\n" +
                    "- Twofish --dec [input filepath] [output dilepath] [-p]:[-k] [key] - for decription input file to output\n" +
                    "Options:\n" +
                    "use [-p] - if you have a password for enc/dec files\n" +
                    "use [-k] - if you want to use the generated hex key\n" +
                    "use [-g] - if you want to generate hex key (only for encryption)");
        }
        System.out.println();
    }

    private byte[] generationKey() {
        byte[] key = new byte[32];
        Random rand = new Random();
        rand.nextBytes(key);
        System.out.print("Hey! Take your generated hex key \nKey=");
        for (int i = 0; i < 32; i++) {
            String tmp = Integer.toHexString(key[i] & 0xff);
            if (tmp.length() != 2) {
                tmp = "0" + tmp;
            }
            System.out.print(tmp);
        }
        System.out.println();
        return key;
    }

    private static byte[] getBytesFromFile(final DataInputStream in) throws IOException {
        byte[] dataBytes = new byte[16];
        int er = in.read(dataBytes, 0, dataBytes.length);
        if (er == -1) {
            return null;
        }
        if (er < 16) {
            for (int i = er; i < 16; i++) {
                dataBytes[i] = (byte) 0xff;
            }
        }
        return dataBytes;
    }

    private static void saveBytesToFile(byte[] bytes, DataOutputStream out) throws IOException {
        out.write(bytes, 0, bytes.length);
    }

    private static void saveBytesToFile(byte[] bytes, DataOutputStream out, int lengthEmpty) throws IOException {
        out.write(bytes, 0, bytes.length - lengthEmpty);
    }

    public void decryption(String inFilepath, String outFilepath, byte[] key) throws IOException {
        encryption(inFilepath, outFilepath, key, DECRYPTION_MOD);
    }

    public void encryption(String inFilepath, String outFilepath, byte[] key) throws IOException {
        encryption(inFilepath, outFilepath, key, ENCRYPTION_MOD);
    }


    public void encryption(String inFilepath, String outFilepath, byte[] key, int mod) throws IOException {
        File file = new File(inFilepath);
        FileInputStream fin = new FileInputStream(file);
        DataInputStream in = new DataInputStream(fin);
        DataOutputStream out = new DataOutputStream(new FileOutputStream(outFilepath));
        byte emptyLength = 0;
        int dataLength = (int) Math.ceil(file.length() / 16);
        int blocksCount = 0;
        switch (mod) {
            case ENCRYPTION_MOD:
                byte[] emptyBytes = {(byte) ((16 - (file.length() % 16)) % 16)};
                System.out.println("Added bytes: " + (int) emptyBytes[0]);
                saveBytesToFile(emptyBytes, out);
                break;
            case DECRYPTION_MOD:
                emptyLength = getEmptyBytes(in);
                System.out.println("Subtracted bytes: " + (int) emptyLength);
                break;
        }

        byte[] data = getBytesFromFile(in);
        byte[] enc_data = null;
        while (data != null) {
            switch (mod) {
                case ENCRYPTION_MOD:
                    enc_data = encryptionBlock(data, key);
                    saveBytesToFile(enc_data, out);
                    break;
                case DECRYPTION_MOD:
                    if (blocksCount != dataLength - 1) {
                        saveBytesToFile(decryptionBlock(data, key), out);
                    } else {
                        saveBytesToFile(decryptionBlock(data, key), out, emptyLength);
                    }
                    break;
            }
            if (mod == ENCRYPTION_MOD) {
                if (blocksCount != dataLength - 1) {
                    correlation(data, enc_data, 0);
                } else {
                    correlation(data, enc_data, emptyLength);
                }
            }
            blocksCount++;
            data = getBytesFromFile(in);
        }

        if (mod == ENCRYPTION_MOD) {
            System.out.println("Correlation: " + (double) correlation / (file.length() * 8));
            zeros = (int) (file.length() * 8 - ones);
            double sdf = file.length() * 8;
            double onesRasp = ones / (sdf);
            double zerosRasp = zeros / (sdf);
            System.out.format("Ones: %f\nZeros: %f\n", onesRasp, zerosRasp);
        }
    }

    private byte getEmptyBytes(DataInputStream ois) throws IOException {
        return ois.readByte();
    }

    private static byte[] getDataBlockFromHexString(String data) {
        byte[] dataBytes = new byte[16];
        for (int i = 0; i < 16; i++) {
            dataBytes[i] = (byte) (int) Integer.valueOf(data.subSequence(i * 2, i * 2 + 2).toString(), 16);
        }
        return dataBytes;
    }

    public byte[] getKeyFromHexString(String key) {
        k = (key.length() / 2) / 8;
        byte[] keyBytes = new byte[key.length() / 2];
        for (int i = 0; i < key.length() / 2; i++) {
            keyBytes[i] = (byte) (int) Integer.valueOf(key.subSequence(i * 2, i * 2 + 2).toString(), 16);
        }
        return keyBytes;
    }

    private byte[] compare(byte[] tmp) {
        int b;
        if (tmp.length < 16) {
            b = 16;
        } else if (tmp.length < 24) {
            b = 24;
        } else if (tmp.length < 32) {
            b = 32;
        } else {
            return null;
        }
        byte[] keyBytes = new byte[b];
        k = b / 8;
        System.out.println("Key size: " + k * 64 + " bit");
        for (int i = 0; i < b; i++) {
            if (i < tmp.length) {
                keyBytes[i] = tmp[i];
            } else {
                keyBytes[i] = 0;
            }
        }
        return keyBytes;
    }

    private void countBitsInString(String data, String enc) {
        for (int i = 0; i < data.length(); i++) {
            int x = Integer.decode(Character.toString(data.charAt(i)));
            int y = Integer.decode(Character.toString(enc.charAt(i)));
            correlation += (2 * x - 1) * (2 * y - 1);
            if (y == 0) zeros++;
            else ones++;
        }
    }

    public void correlation(byte[] data, byte[] enc_data, int emptyBytes) {
        for (int i = 0; i < data.length - emptyBytes; i++) {
            String binStrData = addZeros(Integer.toBinaryString(((int) data[i]) & 0xff));
            String binStrEnc = addZeros(Integer.toBinaryString(((int) enc_data[i]) & 0xff));
            countBitsInString(binStrData, binStrEnc);
        }
    }

    private String addZeros(String binStr) {
        StringBuffer newBinString = new StringBuffer();
        for (int i = 0; i < (8 - binStr.length()); i++) {
            newBinString.append("0");
        }
        newBinString.append(binStr);
        return newBinString.toString();
    }

    public byte[] getKeyFromPassword(String key) {
        byte[] tmp = key.getBytes();
        byte[] keyBytes = compare(tmp);
        return keyBytes;
    }

    public byte polynomMultip(byte x, byte y, int primitive) {
        int shift;
        int result = 0;
        //умножение
        for (int i = 7; i >= 0; i--) {
            shift = (1 << i);
            if (((byte) (x & shift)) != 0) {
                result = result ^ ((y & 0xff) << i);
            }
        }
        //деление по модулю примитивного
        for (int i = 15; i >= 0; i--) {
            shift = (1 << i);
            if (i < 8) break;
            if (((result & shift)) != 0) {
                int tmp = ((primitive) << (i - 8));
                result = result ^ tmp;
            }
        }
        return (byte) (result & 0xff);
    }

    private int multRSMatrix(byte[] vector) {
        int sboxKey = 0;
        int s;
        for (int j = 0; j < 4; j++) {
            s = 0;
            for (int i = 0; i < 8; i++) {
                s = ((s ^ polynomMultip(RS_MATRIX[j * 8 + i], vector[i], RS_PRIMITIVE))) & 0xff;
            }
            sboxKey = sboxKey ^ (s << (j * 8));
        }
        return sboxKey;
    }

    public int multMDSMatrix(byte[] vector) {
        int result = 0;
        int z;
        for (int j = 0; j < 4; j++) {
            z = 0;
            for (int i = 0; i < 4; i++) {
                int tmp = ((int) polynomMultip(MDS_MATRIX[j * 4 + i], vector[i], MDS_PRIMITIVE)) & 0xff;
                z = ((z ^ tmp)) & 0xff;
            }
            result = result ^ (z << (j * 8));
        }
        return result;
    }

    private void scheduleKeys(byte[] key) {
        sboxKeysGen(key);
        subKeysGen(key);
    }

    public void sboxKeysGen(byte[] key) {
        sboxKeys = new int[k];
        for (int i = 0; i < k; i++) {
            byte[] vector = new byte[8];
            for (int j = 0; j < 8; j++) {
                vector[j] = key[i * 8 + j];
            }
            sboxKeys[k - i - 1] = multRSMatrix(vector);
        }
    }

    private int bytesToWord(byte... bytes) {
        return (((int) bytes[0]) & 0xff) ^
                ((((int) bytes[1]) & 0xff) << 8) ^
                ((((int) bytes[2]) & 0xff) << 16) ^
                ((((int) bytes[3]) & 0xff) << 24);
    }

    private byte[] wordToBytes(int word) {
        byte[] bytes = new byte[4];
        bytes[0] = (byte) (word & 0xff);
        bytes[1] = (byte) ((word >> 8) & 0xff);
        bytes[2] = (byte) ((word >> 16) & 0xff);
        bytes[3] = (byte) ((word >> 24) & 0xff);
        return bytes;
    }

    private void subKeysGen(byte[] key) {
        int[] mEven = new int[k];//чётные
        int[] mOdd = new int[k]; //нечетные
        int mID = 0;
        long mod = (long) Math.pow(2, 32);
        int a, b;
        subKeys = new int[40];
        for (int i = 0; i < k; i++) {
            mEven[mID] = bytesToWord(key[i * 8], key[i * 8 + 1], key[i * 8 + 2], key[i * 8 + 3]);
            mOdd[mID] = bytesToWord(key[i * 8 + 4], key[i * 8 + 5], key[i * 8 + 6], key[i * 8 + 7]);
            mID++;
        }
        for (int i = 0; i < 20; i++) {
            a = functionH(2 * i * POL, mEven);
            b = Integer.rotateLeft(functionH((2 * i + 1) * POL, mOdd), 8);
            subKeys[i * 2] = (int) ((a + b) % mod);
            subKeys[i * 2 + 1] = Integer.rotateLeft((int) ((a + 2 * b) % mod), 9);
        }
    }


    public byte[] encryptionBlock(byte[] infoBlock, byte[] key) {
        return encryptionBlock(infoBlock, key, ENCRYPTION_MOD);
    }

    public byte[] decryptionBlock(byte[] infoBlock, byte[] key) {
        return encryptionBlock(infoBlock, key, DECRYPTION_MOD);
    }

    public byte[] encryptionBlock(byte[] infoBlock, byte[] key, int mod) {
        int[] round4Words = new int[4];
        scheduleKeys(key);
        for (int i = 0; i < 4; i++) {
            round4Words[i] = bytesToWord(infoBlock[i * 4], infoBlock[i * 4 + 1], infoBlock[i * 4 + 2], infoBlock[i * 4 + 3]);
        }
        if (mod == ENCRYPTION_MOD) {
            round4Words = whitening(round4Words, IN_WHITENING);
            for (int i = 0; i < ROUNDS; i++) {
                round4Words = round(round4Words, i);
            }
        } else {
            round4Words = whitening(round4Words, OUT_WHITENING);
            round4Words = new int[]{round4Words[2], round4Words[3], round4Words[0], round4Words[1]};
            for (int i = ROUNDS - 1; i >= 0; i--) {
                round4Words = roundDec(round4Words, i);
            }
        }
        if (mod == ENCRYPTION_MOD) {
            int[] tmpWords = {round4Words[2], round4Words[3], round4Words[0], round4Words[1]};
            round4Words = whitening(tmpWords, OUT_WHITENING);
        } else {
            round4Words = whitening(round4Words, IN_WHITENING);
        }
        byte[] outBytes = new byte[16];
        for (int i = 0; i < 4; i++) {
            byte[] word = wordToBytes(round4Words[i]);
            for (int j = 0; j < 4; j++) {
                outBytes[i * 4 + j] = word[j];
            }
        }
        return outBytes;
    }

    private int[] round(int[] in4Words, int roundId) {
        int[] result2Words;
        if (roundId % 2 == 0) {
            result2Words = functionF(roundId, in4Words[0], in4Words[1]);
            in4Words[2] = Integer.rotateRight(result2Words[0] ^ in4Words[2], 1);
            in4Words[3] = result2Words[1] ^ Integer.rotateLeft(in4Words[3], 1);
        } else {
            result2Words = functionF(roundId, in4Words[2], in4Words[3]);
            in4Words[0] = Integer.rotateRight(result2Words[0] ^ in4Words[0], 1);
            in4Words[1] = result2Words[1] ^ Integer.rotateLeft(in4Words[1], 1);
        }
        return in4Words;
    }

    private int[] roundDec(int[] in4Words, int roundId) {
        int[] result2Words; // 2 word length
        if (roundId % 2 == 0) {
            result2Words = functionF(roundId, in4Words[0], in4Words[1]);
            in4Words[2] = result2Words[0] ^ Integer.rotateLeft(in4Words[2], 1);
            in4Words[3] = Integer.rotateRight(result2Words[1] ^ in4Words[3], 1);
        } else {
            result2Words = functionF(roundId, in4Words[2], in4Words[3]);
            in4Words[0] = result2Words[0] ^ Integer.rotateLeft(in4Words[0], 1);
            in4Words[1] = Integer.rotateRight(result2Words[1] ^ in4Words[1], 1);
        }
        return in4Words;
    }

    private int[] whitening(int[] in4Words, int delta) {
        if (in4Words.length != 4)
            throw new WhiteningException("Whitening exception! Block length not equal 4 words(128bit)");
        int[] out4Words = new int[4];
        //System.out.println("Whitening: " + delta);
        for (int i = 0; i < in4Words.length; i++) {
            out4Words[i] = in4Words[i] ^ subKeys[i + delta];
            //System.out.println(Integer.toHexString(subKeys[i + delta]));
        }
        return out4Words;
    }

    private int[] functionF(int roundId, int... in2Words) {
        int resultG0;
        int resultG1;
        long mod = (long) Math.pow(2, 32);
        resultG0 = functionG(in2Words[0]);
        resultG1 = functionG(Integer.rotateLeft(in2Words[1], 8));
        int resultF0 = (int) ((resultG0 + resultG1 + subKeys[2 * roundId + 8]) % mod);
        int resultF1 = (int) ((resultG0 + 2 * resultG1 + subKeys[2 * roundId + 9]) % mod);
        int[] out2Words = {resultF0, resultF1};
        return out2Words;
    }

    private int functionG(int inWord) {
        return functionH(inWord, sboxKeys);
    }

    private int functionH(int inWord, int... listL) {
        int result = 0;
        byte[] tmpBytes = ByteBuffer.allocate(4).putInt(inWord).array();
        byte[] splitWord = {tmpBytes[3], tmpBytes[2], tmpBytes[1], tmpBytes[0]};
        switch (listL.length) {
            case 4:
                tmpBytes = ByteBuffer.allocate(4).putInt(listL[3]).array();
                byte[] splitList3 = {tmpBytes[3], tmpBytes[2], tmpBytes[1], tmpBytes[0]};
                splitWord[0] = (byte) (transformQ1(splitWord[0]) ^ splitList3[0]);
                splitWord[1] = (byte) (transformQ0(splitWord[1]) ^ splitList3[1]);
                splitWord[2] = (byte) (transformQ0(splitWord[2]) ^ splitList3[2]);
                splitWord[3] = (byte) (transformQ1(splitWord[3]) ^ splitList3[3]);
            case 3:
                tmpBytes = ByteBuffer.allocate(4).putInt(listL[2]).array();
                byte[] splitList2 = {tmpBytes[3], tmpBytes[2], tmpBytes[1], tmpBytes[0]};
                splitWord[0] = (byte) (transformQ1(splitWord[0]) ^ splitList2[0]);
                splitWord[1] = (byte) (transformQ1(splitWord[1]) ^ splitList2[1]);
                splitWord[2] = (byte) (transformQ0(splitWord[2]) ^ splitList2[2]);
                splitWord[3] = (byte) (transformQ0(splitWord[3]) ^ splitList2[3]);
            case 2:
                tmpBytes = ByteBuffer.allocate(4).putInt(listL[1]).array();
                byte[] splitList1 = {tmpBytes[3], tmpBytes[2], tmpBytes[1], tmpBytes[0]};
                splitWord[0] = (byte) (transformQ0(splitWord[0]) ^ splitList1[0]);
                splitWord[1] = (byte) (transformQ1(splitWord[1]) ^ splitList1[1]);
                splitWord[2] = (byte) (transformQ0(splitWord[2]) ^ splitList1[2]);
                splitWord[3] = (byte) (transformQ1(splitWord[3]) ^ splitList1[3]);

                tmpBytes = ByteBuffer.allocate(4).putInt(listL[0]).array();
                byte[] splitList0 = {tmpBytes[3], tmpBytes[2], tmpBytes[1], tmpBytes[0]};

                splitWord[0] = (byte) (transformQ0(splitWord[0]) ^ splitList0[0]);
                splitWord[1] = (byte) (transformQ0(splitWord[1]) ^ splitList0[1]);
                splitWord[2] = (byte) (transformQ1(splitWord[2]) ^ splitList0[2]);
                splitWord[3] = (byte) (transformQ1(splitWord[3]) ^ splitList0[3]);

                splitWord[0] = transformQ1(splitWord[0]);
                splitWord[1] = transformQ0(splitWord[1]);
                splitWord[2] = transformQ1(splitWord[2]);
                splitWord[3] = transformQ0(splitWord[3]);
        }
        result = multMDSMatrix(splitWord);
        return result;
    }

    public byte transformQ0(byte x) {
        return transformQ(x, TQ0);
    }

    private byte transformQ1(byte x) {
        return transformQ(x, TQ1);
    }

    public byte transformQ(byte x, byte[][] tableT) {
        byte[] a = new byte[5];
        byte[] b = new byte[5];

        a[0] = (byte) ((x & 0xf0) >> 4);
        b[0] = (byte) (x & 0x0f);
        a[1] = (byte) ((a[0] ^ b[0]) & 0x0f);
        b[1] = (byte) (a[0] ^ rotationRight4bit(b[0], 1) ^ ((8 * a[0]) % 16));
        a[2] = tableT[0][a[1]];
        b[2] = tableT[1][b[1]];
        a[3] = (byte) ((a[2] ^ b[2]) & 0x0f);
        b[3] = (byte) (a[2] ^ rotationRight4bit(b[2], 1) ^ ((8 * a[2]) % 16));
        a[4] = tableT[2][a[3]];
        b[4] = tableT[3][b[3]];
        return (byte) (16 * b[4] + a[4]);
    }


    public byte rotationRight4bit(byte x, int step) {
        char r = (char) (x << 4);
        for (int i = 0; i < step; i++) {
            r = (char) (r >> 1);
            r = (char) ((r & 0xf0) ^ ((r & 0x0f) << 4));
        }
        return (byte) (r >> 4);
    }

    private static void printBinStringln(String str) {
        printBinString(str);
        System.out.println();
    }

    private static void printBinString(String str) {
        StringBuffer sb = new StringBuffer();
        for (int j = 0; j < 32 - str.length(); j++) {
            sb.append("0");
        }
        sb.append(str);
        for (int i = 0; i < sb.length(); i++) {
            System.out.print(sb.charAt(i));
            if (i % 4 == 3) {
                System.out.print(" ");
            }
        }
    }


}
