package com.example.cryptographic_library.algorithm.symmetric;

import java.util.Arrays;

public class AES {
    private static final int BLOCK_SIZE = 16;
    private static final int[] SBOX = {
            0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
            0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
            0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
            0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
            0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
            0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
            0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
            0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
            0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
            0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
            0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
            0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
            0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
            0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
            0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
            0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
    };//填充标准S盒
    private static final int[] INV_SBOX = {
            0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
            0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
            0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
            0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
            0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
            0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
            0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
            0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
            0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
            0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
            0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
            0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
            0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
            0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
            0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
            0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
    };//填充逆S盒
    private static final int[] RCON = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};

    private final int rounds;
    private final int[][] roundKeys;
//    private final byte[] iv;

    private void validateKey(byte[] key) {
        if (key == null) throw new IllegalArgumentException("密钥不能为空");
        Boolean validLength = key.length == 16 || key.length == 24 || key.length == 32;
        if (!validLength) {
            throw new IllegalArgumentException("无效的AES密钥长度，必须为16/24/32字节");
        }
    }


    public AES(byte[] key) {
        validateKey(key);
        //this.iv = Arrays.copyOf(iv, BLOCK_SIZE);
        this.rounds = key.length / 4 + 6; // 10/12/14 rounds
        this.roundKeys = keyExpansion(key);
    }

    // CBC加密
    public byte[] encrypt(byte[] plaintext) {
        byte[] padded = applyPadding(plaintext);
        byte[] ciphertext = new byte[padded.length];
        //byte[] prevBlock = Arrays.copyOf(iv, BLOCK_SIZE);

        for (int i = 0; i < padded.length; i += BLOCK_SIZE) {
            byte[] block = Arrays.copyOfRange(padded, i, i + BLOCK_SIZE);
            //xorBlocks(block, prevBlock);
            encryptBlock(block);
            System.arraycopy(block, 0, ciphertext, i, BLOCK_SIZE);
            //prevBlock = Arrays.copyOf(block, BLOCK_SIZE);
        }
        return ciphertext;
    }

    // CBC解密
    public byte[] decrypt(byte[] ciphertext) {
        byte[] plaintext = new byte[ciphertext.length];
        //byte[] prevBlock = Arrays.copyOf(iv, BLOCK_SIZE);

        for (int i = 0; i < ciphertext.length; i += BLOCK_SIZE) {
            byte[] block = Arrays.copyOfRange(ciphertext, i, i + BLOCK_SIZE);
            //byte[] temp = Arrays.copyOf(block, BLOCK_SIZE);

            decryptBlock(block);
            //xorBlocks(block, prevBlock);
            System.arraycopy(block, 0, plaintext, i, BLOCK_SIZE);
            //prevBlock = temp;
        }
        return removePadding(plaintext);
    }

    // 轮密钥加
    private void addRoundKey(byte[] state, int round) {
        for (int i = 0; i < BLOCK_SIZE; i++) {
            int word = roundKeys[round][i / 4];
            byte keyByte = (byte) ((word >>> (24 - 8 * (i % 4))) & 0xFF);
            state[i] ^= keyByte;
        }
    }

    // 字节替换（加密用）
    private void subBytes(byte[] state) {
        for (int i = 0; i < BLOCK_SIZE; i++) {
            state[i] = (byte) SBOX[state[i] & 0xFF];
        }
    }

    // 逆字节替换（解密用）
    private void invSubBytes(byte[] state) {
        for (int i = 0; i < BLOCK_SIZE; i++) {
            state[i] = (byte) INV_SBOX[state[i] & 0xFF];
        }
    }

    // 行移位（加密用）
    private void shiftRows(byte[] state) {
        byte[] temp = new byte[BLOCK_SIZE];
        // 第0行不移位
        System.arraycopy(state, 0, temp, 0, 4);
        // 第1行左移1字节
        temp[4] = state[5];
        temp[5] = state[6];
        temp[6] = state[7];
        temp[7] = state[4];
        // 第2行左移2字节
        temp[8] = state[10];
        temp[9] = state[11];
        temp[10] = state[8];
        temp[11] = state[9];
        // 第3行左移3字节
        temp[12] = state[15];
        temp[13] = state[12];
        temp[14] = state[13];
        temp[15] = state[14];
        System.arraycopy(temp, 0, state, 0, BLOCK_SIZE);
    }

    // 逆行移位（解密用）
    private void invShiftRows(byte[] state) {
        byte[] temp = new byte[BLOCK_SIZE];
        // 第0行不移位
        System.arraycopy(state, 0, temp, 0, 4);
        // 第1行右移1字节
        temp[4] = state[7];
        temp[5] = state[4];
        temp[6] = state[5];
        temp[7] = state[6];
        // 第2行右移2字节
        temp[8] = state[10];
        temp[9] = state[11];
        temp[10] = state[8];
        temp[11] = state[9];
        // 第3行右移3字节
        temp[12] = state[13];
        temp[13] = state[14];
        temp[14] = state[15];
        temp[15] = state[12];
        System.arraycopy(temp, 0, state, 0, BLOCK_SIZE);
    }

    // 列混淆（加密用）
    private void mixColumns(byte[] state) {
        for (int i = 0; i < 4; i++) {
            int s0 = state[i * 4] & 0xFF;
            int s1 = state[i * 4 + 1] & 0xFF;
            int s2 = state[i * 4 + 2] & 0xFF;
            int s3 = state[i * 4 + 3] & 0xFF;

            state[i * 4] = (byte) (mul(0x02, s0) ^ mul(0x03, s1) ^ s2 ^ s3);
            state[i * 4 + 1] = (byte) (s0 ^ mul(0x02, s1) ^ mul(0x03, s2) ^ s3);
            state[i * 4 + 2] = (byte) (s0 ^ s1 ^ mul(0x02, s2) ^ mul(0x03, s3));
            state[i * 4 + 3] = (byte) (mul(0x03, s0) ^ s1 ^ s2 ^ mul(0x02, s3));
        }
    }

    // 逆列混淆（解密用）
    private void invMixColumns(byte[] state) {
        for (int i = 0; i < 4; i++) {
            int s0 = state[i * 4] & 0xFF;
            int s1 = state[i * 4 + 1] & 0xFF;
            int s2 = state[i * 4 + 2] & 0xFF;
            int s3 = state[i * 4 + 3] & 0xFF;

            state[i * 4] = (byte) (mul(0x0e, s0) ^ mul(0x0b, s1) ^ mul(0x0d, s2) ^ mul(0x09, s3));
            state[i * 4 + 1] = (byte) (mul(0x09, s0) ^ mul(0x0e, s1) ^ mul(0x0b, s2) ^ mul(0x0d, s3));
            state[i * 4 + 2] = (byte) (mul(0x0d, s0) ^ mul(0x09, s1) ^ mul(0x0e, s2) ^ mul(0x0b, s3));
            state[i * 4 + 3] = (byte) (mul(0x0b, s0) ^ mul(0x0d, s1) ^ mul(0x09, s2) ^ mul(0x0e, s3));
        }
    }


    // 核心加密块处理
    private void encryptBlock(byte[] state) {
        addRoundKey(state, 0);
        for (int round = 1; round <= rounds; round++) {
            subBytes(state);
            shiftRows(state);
            if (round < rounds) mixColumns(state);
            addRoundKey(state, round);
        }
    }

    // 核心解密块处理
    private void decryptBlock(byte[] state) {
        addRoundKey(state, rounds);
        for (int round = rounds - 1; round >= 0; round--) {
            invShiftRows(state);
            invSubBytes(state);
            addRoundKey(state, round);
            if (round > 0) invMixColumns(state);
        }
    }

    // 密钥扩展实现
    private int[][] keyExpansion(byte[] key) {
        int nk = key.length / 4;
        int[] w = new int[4 * (rounds + 1)];

        // 初始密钥拷贝
        for (int i = 0; i < nk; i++) {
            w[i] = ((key[4 * i] & 0xFF) << 24) |
                    ((key[4 * i + 1] & 0xFF) << 16) |
                    ((key[4 * i + 2] & 0xFF) << 8) |
                    (key[4 * i + 3] & 0xFF);
        }

        // 密钥扩展算法
        for (int i = nk; i < 4 * (rounds + 1); i++) {
            int temp = w[i - 1];
            if (i % nk == 0) {
                temp = subWord(rotWord(temp)) ^ (RCON[(i / nk) - 1] << 24);
            } else if (nk > 6 && i % nk == 4) {
                temp = subWord(temp);
            }
            w[i] = w[i - nk] ^ temp;
        }
        return groupWords(w);
    }

    private int[][] groupWords(int[] w) {
        int[][] keys = new int[rounds + 1][4];
        for (int i = 0; i <= rounds; i++) {
            System.arraycopy(w, i * 4, keys[i], 0, 4);
        }
        return keys;
    }

    private int subWord(int word) {
        return (SBOX[(word >> 24) & 0xFF] << 24) |
                (SBOX[(word >> 16) & 0xFF] << 16) |
                (SBOX[(word >> 8) & 0xFF] << 8) |
                SBOX[word & 0xFF];
    }

    private int rotWord(int word) {
        return (word << 8) | ((word >> 24) & 0xFF);
    }

    // CBC专用辅助方法
    private void xorBlocks(byte[] a, byte[] b) {
        for (int i = 0; i < BLOCK_SIZE; i++) {
            a[i] ^= b[i];
        }
    }

    //PKCS7填充
    private byte[] applyPadding(byte[] input) {
        int padding = BLOCK_SIZE - (input.length % BLOCK_SIZE);
        byte[] padded = Arrays.copyOf(input, input.length + padding);
        Arrays.fill(padded, input.length, padded.length, (byte) padding);
        return padded;
    }

    private byte[] removePadding(byte[] input) {
        int padding = input[input.length - 1] & 0xFF;
        return Arrays.copyOf(input, input.length - padding);
    }

    // 安全擦除敏感数据
    public void clearKeys() {
        for (int[] arr : roundKeys) Arrays.fill(arr, 0);
    }

    // Galois Field乘法辅助方法
    private static int mul(int a, int b) {
        int result = 0;
        while (b > 0) {
            if ((b & 1) != 0) result ^= a;
            a = (a << 1) ^ ((a & 0x80) != 0 ? 0x1b : 0);
            b >>= 1;
        }
        return result;
    }

    public static void main(String[] args) {
        // 初始化参数（使用固定值方便验证）
        byte[] key = "ThisIsASecretKey".getBytes();  // 128-bit密钥
        //byte[] iv = "InitializationIV".getBytes();   // 16字节初始化向量
        String plainText = "lzy2022211651";          // 测试明文

        // 初始化AES实例
        AES aes = new AES(key);

        try {
            // 加密过程
            byte[] cipherText = aes.encrypt(plainText.getBytes());
            System.out.println("加密结果 (HEX): " + bytesToHex(cipherText));

            // 解密过程
            byte[] decrypted = aes.decrypt(cipherText);
            System.out.println("解密结果: " + new String(decrypted));

        } finally {
            aes.clearKeys(); // 安全擦除密钥
        }

    }

    // 字节数组转十六进制字符串（用于输出验证）
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

}


