package com.example.cryptographic_library.algorithm.symmetric;

import java.nio.ByteBuffer;
import java.util.Arrays;

public class SM4 {
    // 算法参数
    private static final int BLOCK_SIZE = 128; // 分组长度（bits）
    private static final int ROUNDS = 32;      // 加密轮数
    private static final int BLOCK_BYTES = BLOCK_SIZE / 8;

    // S盒（国家标准给定的置换表）
    private static final byte[] S_BOX = {
            (byte)0xD6, (byte)0x90, (byte)0xE9, (byte)0xFE, (byte)0xCC, (byte)0xE1, (byte)0x3D, (byte)0xB7,
            (byte)0x16, (byte)0xB6, (byte)0x14, (byte)0xC2, (byte)0x28, (byte)0xFB, (byte)0x2C, (byte)0x05,
            (byte)0x2B, (byte)0x67, (byte)0x9A, (byte)0x76, (byte)0x2A, (byte)0xBE, (byte)0x04, (byte)0xC3,
            (byte)0xAA, (byte)0x44, (byte)0x13, (byte)0x26, (byte)0x49, (byte)0x86, (byte)0x06, (byte)0x99,
            (byte)0x9C, (byte)0x42, (byte)0x50, (byte)0xF4, (byte)0x91, (byte)0xEF, (byte)0x98, (byte)0x7A,
            (byte)0x33, (byte)0x54, (byte)0x0B, (byte)0x43, (byte)0xED, (byte)0xCF, (byte)0xAC, (byte)0x62,
            (byte)0xE4, (byte)0xB3, (byte)0x1C, (byte)0xA9, (byte)0xC9, (byte)0x08, (byte)0xE8, (byte)0x95,
            (byte)0x80, (byte)0xDF, (byte)0x94, (byte)0xFA, (byte)0x75, (byte)0x8F, (byte)0x3F, (byte)0xA6,
            (byte)0x47, (byte)0x07, (byte)0xA7, (byte)0xFC, (byte)0xF3, (byte)0x73, (byte)0x17, (byte)0xBA,
            (byte)0x83, (byte)0x59, (byte)0x3C, (byte)0x19, (byte)0xE6, (byte)0x85, (byte)0x4F, (byte)0xA8,
            (byte)0x68, (byte)0x6B, (byte)0x81, (byte)0xB2, (byte)0x71, (byte)0x64, (byte)0xDA, (byte)0x8B,
            (byte)0xF8, (byte)0xEB, (byte)0x0F, (byte)0x4B, (byte)0x70, (byte)0x56, (byte)0x9D, (byte)0x35,
            (byte)0x1E, (byte)0x24, (byte)0x0E, (byte)0x5E, (byte)0x63, (byte)0x58, (byte)0xD1, (byte)0xA2,
            (byte)0x25, (byte)0x22, (byte)0x7C, (byte)0x3B, (byte)0x01, (byte)0x21, (byte)0x78, (byte)0x87,
            (byte)0xD4, (byte)0x00, (byte)0x46, (byte)0x57, (byte)0x9F, (byte)0xD3, (byte)0x27, (byte)0x52,
            (byte)0x4C, (byte)0x36, (byte)0x02, (byte)0xE7, (byte)0xA0, (byte)0xC4, (byte)0xC8, (byte)0x9E,
            (byte)0xEA, (byte)0xBF, (byte)0x8A, (byte)0xD2, (byte)0x40, (byte)0xC7, (byte)0x38, (byte)0xB5,
            (byte)0xA3, (byte)0xF7, (byte)0xF2, (byte)0xCE, (byte)0xF9, (byte)0x61, (byte)0x15, (byte)0xA1,
            (byte)0xE0, (byte)0xAE, (byte)0x5D, (byte)0xA4, (byte)0x9B, (byte)0x34, (byte)0x1A, (byte)0x55,
            (byte)0xAD, (byte)0x93, (byte)0x32, (byte)0x30, (byte)0xF5, (byte)0x8C, (byte)0xB1, (byte)0xE3,
            (byte)0x1D, (byte)0xF6, (byte)0xE2, (byte)0x2E, (byte)0x82, (byte)0x66, (byte)0xCA, (byte)0x60,
            (byte)0xC0, (byte)0x29, (byte)0x23, (byte)0xAB, (byte)0x0D, (byte)0x53, (byte)0x4E, (byte)0x6F,
            (byte)0xD5, (byte)0xDB, (byte)0x37, (byte)0x45, (byte)0xDE, (byte)0xFD, (byte)0x8E, (byte)0x2F,
            (byte)0x03, (byte)0xFF, (byte)0x6A, (byte)0x72, (byte)0x6D, (byte)0x6C, (byte)0x5B, (byte)0x51,
            (byte)0x8D, (byte)0x1B, (byte)0xAF, (byte)0x92, (byte)0xBB, (byte)0xDD, (byte)0xBC, (byte)0x7F,
            (byte)0x11, (byte)0xD9, (byte)0x5C, (byte)0x41, (byte)0x1F, (byte)0x10, (byte)0x5A, (byte)0xD8,
            (byte)0x0A, (byte)0xC1, (byte)0x31, (byte)0x88, (byte)0xA5, (byte)0xCD, (byte)0x7B, (byte)0xBD,
            (byte)0x2D, (byte)0x74, (byte)0xD0, (byte)0x12, (byte)0xB8, (byte)0xE5, (byte)0xB4, (byte)0xB0,
            (byte)0x89, (byte)0x69, (byte)0x97, (byte)0x4A, (byte)0x0C, (byte)0x96, (byte)0x77, (byte)0x7E,
            (byte)0x65, (byte)0xB9, (byte)0xF1, (byte)0x09, (byte)0xC5, (byte)0x6E, (byte)0xC6, (byte)0x84,
            (byte)0x18, (byte)0xF0, (byte)0x7D, (byte)0xEC, (byte)0x3A, (byte)0xDC, (byte)0x4D, (byte)0x20,
            (byte)0x79, (byte)0xEE, (byte)0x5F, (byte)0x3E, (byte)0xD7, (byte)0xCB, (byte)0x39, (byte)0x48
    };


    // 系统参数FK
    private static final int[] FK = {
            0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC
    };

    // 固定参数CK
    private static final int[] CK = {
            0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
            0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
            0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
            0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
            0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
            0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
            0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
            0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
    };

    private final int[] roundKeys = new int[ROUNDS]; // 轮密钥

    public SM4(byte[] key) {
        validateKey(key);
        generateRoundKeys(key);
    }

    // 完整加密流程（自动填充）
    public byte[] encrypt(byte[] plaintext) {
        byte[] padded = pkcs7Pad(plaintext, BLOCK_BYTES);
        return processBlocks(padded, true);
    }

    // 完整解密流程（自动去填充）
    public byte[] decrypt(byte[] ciphertext) {
        byte[] decrypted = processBlocks(ciphertext, false);
        return pkcs7Unpad(decrypted);
    }

    // 密钥扩展算法
    private void generateRoundKeys(byte[] key) {
        int[] mk = bytesToWords(key);
        int[] k = new int[4];

        // 初始化轮密钥
        for (int i = 0; i < 4; i++) {
            k[i] = mk[i] ^ FK[i];
        }

        // 生成轮密钥
        for (int i = 0; i < ROUNDS; i++) {
            int a = k[(i + 1) % 4];
            int b = k[(i + 2) % 4];
            int c = k[(i + 3) % 4];

            int tmp = a ^ b ^ c ^ CK[i];
            tmp = sBoxTrans(tmp);
            tmp = tmp ^ leftRotate(tmp, 13) ^ leftRotate(tmp, 23);
            roundKeys[i] = k[i%4] ^ tmp;
            k[i % 4] = roundKeys[i];
        }
    }

    // 轮函数F
    private int f(int x0, int x1, int x2, int x3, int rk) {
        int tmp = x1 ^ x2 ^ x3 ^ rk;
        tmp = sBoxTrans(tmp);
        return x0 ^ tmp ^ leftRotate(tmp, 2) ^ leftRotate(tmp, 10)
                ^ leftRotate(tmp, 18) ^ leftRotate(tmp, 24);
    }

    // 分组处理
    private byte[] processBlocks(byte[] input, boolean encrypt) {
        ByteBuffer output = ByteBuffer.allocate(input.length);

        for (int i = 0; i < input.length; i += BLOCK_BYTES) {
            byte[] block = Arrays.copyOfRange(input, i, i + BLOCK_BYTES);
            output.put(processBlock(block, encrypt));
        }

        return output.array();
    }

    // 单个分组处理
    private byte[] processBlock(byte[] block, boolean encrypt) {
        int[] x = bytesToWords(block);

        for (int r = 0; r < ROUNDS; r++) {
            int rk = encrypt ? roundKeys[r] : roundKeys[ROUNDS - 1 - r];
            int tmp = f(x[0], x[1], x[2], x[3], rk);
            x = new int[]{x[1], x[2], x[3], tmp};
        }

        // 最终反序
        return wordsToBytes(new int[]{x[3], x[2], x[1], x[0]});
    }

    // S盒置换（4字节处理）
    private int sBoxTrans(int word) {
        int result = 0;
        for (int i = 0; i < 4; i++) {
            int b = (word >>> (24 - i*8)) & 0xFF;
            result |= (S_BOX[b] & 0xFF) << (24 - i*8);
        }
        return result;
    }

    // 循环左移
    private int leftRotate(int x, int n) {
        return (x << n) | (x >>> (32 - n));
    }

    // 以下为辅助方法（与RC6类似）-------------------------
    private void validateKey(byte[] key) {
        if (key.length != 16) {
            throw new IllegalArgumentException("密钥必须为128位（16字节）");
        }
    }

    private static byte[] pkcs7Pad(byte[] input, int blockSize) {
        int padding = blockSize - (input.length % blockSize);
        padding = padding == 0 ? blockSize : padding;
        byte[] padded = Arrays.copyOf(input, input.length + padding);
        Arrays.fill(padded, input.length, padded.length, (byte) padding);
        return padded;
    }

    private static byte[] pkcs7Unpad(byte[] input) {
        if (input.length == 0) throw new IllegalArgumentException("空输入");
        int padding = input[input.length - 1] & 0xFF;
        return Arrays.copyOf(input, input.length - padding);
    }

    private static int[] bytesToWords(byte[] bytes) {
        ByteBuffer buffer = ByteBuffer.wrap(bytes);
        return new int[]{buffer.getInt(), buffer.getInt(), buffer.getInt(), buffer.getInt()};
    }

    private static byte[] wordsToBytes(int[] words) {
        ByteBuffer buffer = ByteBuffer.allocate(16);
        buffer.putInt(words[0]);
        buffer.putInt(words[1]);
        buffer.putInt(words[2]);
        buffer.putInt(words[3]);
        return buffer.array();
    }

    // 测试用例
    public static void main(String[] args) {
        byte[] key = "1234567890abcdef".getBytes();
        byte[] plaintext = "Hello SM4!".getBytes();

        SM4 sm4 = new SM4(key);
        byte[] ciphertext = sm4.encrypt(plaintext);
        byte[] decrypted = sm4.decrypt(ciphertext);

        System.out.println("密钥："+ bytesToHex(key));
        System.out.println("加密结果：" + bytesToHex(ciphertext));
        System.out.println("解密结果：" + new String(decrypted));
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xFF));
        }
        return sb.toString();
    }
}
