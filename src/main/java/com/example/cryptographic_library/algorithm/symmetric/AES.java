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

    // ECB加密
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

    // ECB解密
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

    // 核心加密块处理
    public void encryptBlock(byte[] state) {
        addRoundKey(state, 0);
        for (int round = 1; round <= rounds; round++) {
            subBytes(state);
            shiftRows(state);
            if (round < rounds) mixColumns(state);
            addRoundKey(state, round);
        }
    }

    // 核心解密块处理
    public void decryptBlock(byte[] state) {
        addRoundKey(state, rounds);
        for (int round = rounds - 1; round >= 0; round--) {
            invShiftRows(state);
            invSubBytes(state);
            addRoundKey(state, round);
            if (round > 0) invMixColumns(state);
        }
    }

    // 轮密钥加
    private void addRoundKey(byte[] state, int round) {
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                // 状态数组是按列顺序排列的
                // state[i*4+j]表示第j行第i列的值
                state[i*4 + j] ^= ((roundKeys[round][i] >>> (24 - 8 * j)) & 0xFF);
            }
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
        
        // 注意：state是按列存储的（AES标准），所以需要正确映射索引
        
        // 第0行不移位
        temp[0] = state[0];  // (0,0)
        temp[4] = state[4];  // (0,1)  
        temp[8] = state[8];  // (0,2)
        temp[12] = state[12]; // (0,3)
        
        // 第1行左移1字节
        temp[1] = state[5];  // (1,0) <- (1,1)
        temp[5] = state[9];  // (1,1) <- (1,2)
        temp[9] = state[13]; // (1,2) <- (1,3)
        temp[13] = state[1]; // (1,3) <- (1,0)
        
        // 第2行左移2字节
        temp[2] = state[10]; // (2,0) <- (2,2)
        temp[6] = state[14]; // (2,1) <- (2,3)
        temp[10] = state[2]; // (2,2) <- (2,0)
        temp[14] = state[6]; // (2,3) <- (2,1)
        
        // 第3行左移3字节
        temp[3] = state[15]; // (3,0) <- (3,3)
        temp[7] = state[3];  // (3,1) <- (3,0)
        temp[11] = state[7]; // (3,2) <- (3,1)
        temp[15] = state[11]; // (3,3) <- (3,2)
        
        System.arraycopy(temp, 0, state, 0, BLOCK_SIZE);
    }

    // 逆行移位（解密用）
    private void invShiftRows(byte[] state) {
        byte[] temp = new byte[BLOCK_SIZE];
        
        // 第0行不移位
        temp[0] = state[0];
        temp[4] = state[4];
        temp[8] = state[8];
        temp[12] = state[12];
        
        // 第1行右移1字节
        temp[1] = state[13];
        temp[5] = state[1];
        temp[9] = state[5];
        temp[13] = state[9];
        
        // 第2行右移2字节
        temp[2] = state[10];
        temp[6] = state[14];
        temp[10] = state[2];
        temp[14] = state[6];
        
        // 第3行右移3字节
        temp[3] = state[7];
        temp[7] = state[11];
        temp[11] = state[15];
        temp[15] = state[3];
        
        System.arraycopy(temp, 0, state, 0, BLOCK_SIZE);
    }

    // 列混淆（加密用）
    private void mixColumns(byte[] state) {
        for (int c = 0; c < 4; c++) {
            int col = c * 4;
            byte s0 = state[col];
            byte s1 = state[col + 1];
            byte s2 = state[col + 2];
            byte s3 = state[col + 3];
            
            byte t0 = (byte)(mul(0x02, s0 & 0xff) ^ mul(0x03, s1 & 0xff) ^ (s2 & 0xff) ^ (s3 & 0xff));
            byte t1 = (byte)((s0 & 0xff) ^ mul(0x02, s1 & 0xff) ^ mul(0x03, s2 & 0xff) ^ (s3 & 0xff));
            byte t2 = (byte)((s0 & 0xff) ^ (s1 & 0xff) ^ mul(0x02, s2 & 0xff) ^ mul(0x03, s3 & 0xff));
            byte t3 = (byte)(mul(0x03, s0 & 0xff) ^ (s1 & 0xff) ^ (s2 & 0xff) ^ mul(0x02, s3 & 0xff));
            
            state[col] = t0;
            state[col + 1] = t1;
            state[col + 2] = t2;
            state[col + 3] = t3;
        }
    }

    // 逆列混淆（解密用）
    private void invMixColumns(byte[] state) {
        for (int c = 0; c < 4; c++) {
            int col = c * 4;
            byte s0 = state[col];
            byte s1 = state[col + 1];
            byte s2 = state[col + 2];
            byte s3 = state[col + 3];
            
            byte t0 = (byte)(mul(0x0e, s0 & 0xff) ^ mul(0x0b, s1 & 0xff) ^ mul(0x0d, s2 & 0xff) ^ mul(0x09, s3 & 0xff));
            byte t1 = (byte)(mul(0x09, s0 & 0xff) ^ mul(0x0e, s1 & 0xff) ^ mul(0x0b, s2 & 0xff) ^ mul(0x0d, s3 & 0xff));
            byte t2 = (byte)(mul(0x0d, s0 & 0xff) ^ mul(0x09, s1 & 0xff) ^ mul(0x0e, s2 & 0xff) ^ mul(0x0b, s3 & 0xff));
            byte t3 = (byte)(mul(0x0b, s0 & 0xff) ^ mul(0x0d, s1 & 0xff) ^ mul(0x09, s2 & 0xff) ^ mul(0x0e, s3 & 0xff));
            
            state[col] = t0;
            state[col + 1] = t1;
            state[col + 2] = t2;
            state[col + 3] = t3;
        }
    }

    // 密钥扩展实现
    private int[][] keyExpansion(byte[] key) {
        int nk = key.length / 4;
        int nb = 4; // AES block size always 4 words (128 bits)
        int nr = rounds;
        int[] w = new int[nb * (nr + 1)];

        // 初始密钥拷贝
        for (int i = 0; i < nk; i++) {
            w[i] = ((key[4 * i] & 0xFF) << 24) |
                    ((key[4 * i + 1] & 0xFF) << 16) |
                    ((key[4 * i + 2] & 0xFF) << 8) |
                    (key[4 * i + 3] & 0xFF);
        }

        // 密钥扩展算法
        for (int i = nk; i < nb * (nr + 1); i++) {
            int temp = w[i - 1];
            if (i % nk == 0) {
                temp = subWord(rotWord(temp)) ^ (RCON[i / nk - 1] << 24);
            } else if (nk > 6 && i % nk == 4) {
                temp = subWord(temp);
            }
            w[i] = w[i - nk] ^ temp;
        }
        
        // 转换为轮密钥格式
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
        if (padding == 0) {
            padding = BLOCK_SIZE; // 如果明文长度正好是块大小的倍数，添加一个完整的填充块
        }
        byte[] padded = Arrays.copyOf(input, input.length + padding);
        Arrays.fill(padded, input.length, padded.length, (byte) padding);
        return padded;
    }

    private byte[] removePadding(byte[] input) {
        if (input.length == 0 || input.length % BLOCK_SIZE != 0) {
            throw new IllegalArgumentException("无效的填充数据: 长度必须是16的倍数且不为0");
        }
        
        int padding = input[input.length - 1] & 0xFF;
        
        // 检查填充值的有效范围
        if (padding <= 0 || padding > BLOCK_SIZE) {
            throw new IllegalArgumentException("无效的填充值: " + padding);
        }
        
        // 验证所有填充字节是否一致
        for (int i = input.length - padding; i < input.length; i++) {
            if ((input[i] & 0xFF) != padding) {
                throw new IllegalArgumentException("无效的填充格式");
            }
        }
        
        return Arrays.copyOf(input, input.length - padding);
    }

    // 安全擦除敏感数据
    public void clearKeys() {
        for (int[] arr : roundKeys) Arrays.fill(arr, 0);
    }

    // Galois Field乘法辅助方法
    private static int mul(int a, int b) {
        int p = 0;
        for (int i = 0; i < 8; i++) {
            if ((b & 1) != 0) {
                p ^= a;
            }
            boolean highBitSet = (a & 0x80) != 0;
            a <<= 1;
            if (highBitSet) {
                a ^= 0x1b; // x^8 + x^4 + x^3 + x + 1
            }
            b >>= 1;
        }
        return p & 0xff;
    }

    /**
     * 使用已知答案测试验证AES实现
     * @return 测试结果，true表示通过所有测试
     */
    public static boolean runKnownAnswerTest() {
        boolean allTestsPassed = true;
        
        // 测试向量1: 128位密钥
        byte[] key1 = hexToBytes("000102030405060708090a0b0c0d0e0f");
        byte[] plaintext1 = hexToBytes("00112233445566778899aabbccddeeff");
        byte[] expected1 = hexToBytes("69c4e0d86a7b0430d8cdb78070b4c55a");
        
        // 测试向量2: 192位密钥
        byte[] key2 = hexToBytes("000102030405060708090a0b0c0d0e0f1011121314151617");
        byte[] plaintext2 = hexToBytes("00112233445566778899aabbccddeeff");
        byte[] expected2 = hexToBytes("dda97ca4864cdfe06eaf70a0ec0d7191");
        
        // 测试向量3: 256位密钥
        byte[] key3 = hexToBytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        byte[] plaintext3 = hexToBytes("00112233445566778899aabbccddeeff");
        byte[] expected3 = hexToBytes("8ea2b7ca516745bfeafc49904b496089");
        
        try {
            // 测试1
            System.out.println("--------- AES-128 测试 ---------");
            AES aes1 = new AES(key1);
            System.out.println("原始明文: " + bytesToHex(plaintext1));
            
            byte[] block1 = Arrays.copyOf(plaintext1, 16);
            aes1.encryptBlock(block1); // 直接使用encryptBlock，跳过填充
            System.out.println("加密结果: " + bytesToHex(block1));
            System.out.println("预期结果: " + bytesToHex(expected1));
            
            boolean test1Passed = Arrays.equals(block1, expected1);
            System.out.println("AES-128 test: " + (test1Passed ? "pass" : "fail"));
            
            if (!test1Passed) {
                // 打印轮密钥验证
                System.out.println("调试信息 - 前几个轮密钥:");
                for (int i = 0; i < Math.min(3, aes1.roundKeys.length); i++) {
                    System.out.println("  轮密钥 " + i + ": " + 
                            String.format("%08x %08x %08x %08x", 
                                    aes1.roundKeys[i][0], 
                                    aes1.roundKeys[i][1],
                                    aes1.roundKeys[i][2],
                                    aes1.roundKeys[i][3]));
                }
            }
            
            allTestsPassed &= test1Passed;
            
            // 测试2 (如果支持192位密钥)
            try {
                System.out.println("\n--------- AES-192 测试 ---------");
                AES aes2 = new AES(key2);
                System.out.println("原始明文: " + bytesToHex(plaintext2));
                
                byte[] block2 = Arrays.copyOf(plaintext2, 16);
                aes2.encryptBlock(block2); // 直接使用encryptBlock，跳过填充
                System.out.println("加密结果: " + bytesToHex(block2));
                System.out.println("预期结果: " + bytesToHex(expected2));
                
                boolean test2Passed = Arrays.equals(block2, expected2);
                System.out.println("AES-192 test: " + (test2Passed ? "pass" : "fail"));
                allTestsPassed &= test2Passed;
            } catch (Exception e) {
                System.out.println("AES-192 test: 跳过 - " + e.getMessage());
            }
            
            // 测试3 (如果支持256位密钥)
            try {
                System.out.println("\n--------- AES-256 测试 ---------");
                AES aes3 = new AES(key3);
                System.out.println("原始明文: " + bytesToHex(plaintext3));
                
                byte[] block3 = Arrays.copyOf(plaintext3, 16);
                aes3.encryptBlock(block3); // 直接使用encryptBlock，跳过填充
                System.out.println("加密结果: " + bytesToHex(block3));
                System.out.println("预期结果: " + bytesToHex(expected3));
                
                boolean test3Passed = Arrays.equals(block3, expected3);
                System.out.println("AES-256 test: " + (test3Passed ? "pass" : "fail"));
                allTestsPassed &= test3Passed;
            } catch (Exception e) {
                System.out.println("AES-256 test: 跳过 - " + e.getMessage());
            }
            
            // 测试自加密解密
            System.out.println("\n--------- 加解密一致性测试 ---------");
            String testText = "TestAESImplementation";
            AES aes = new AES(key1);
            byte[] encrypted = aes.encrypt(testText.getBytes());
            byte[] decrypted = aes.decrypt(encrypted);
            String decryptedText = new String(decrypted);
            boolean roundTripTest = testText.equals(decryptedText);
            System.out.println("加密-解密往返测试: " + (roundTripTest ? "通过" : "失败"));
            allTestsPassed &= roundTripTest;
            
            return allTestsPassed;
            
        } catch (Exception e) {
            System.out.println("AES测试失败: " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }
    
    // 十六进制字符串转字节数组
    private static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }

    public static void main(String[] args) {
        // 运行已知答案测试
        System.out.println("执行AES已知答案测试");
        boolean testsPassed = runKnownAnswerTest();
        System.out.println("已知答案测试结果: " + (testsPassed ? "全部通过" : "测试失败"));
        System.out.println();
        
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
            
            // 显式验证加解密是否一致
            System.out.println("验证结果: " + plainText.equals(new String(decrypted)));

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


