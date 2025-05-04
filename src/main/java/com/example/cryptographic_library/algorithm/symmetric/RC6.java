package com.example.cryptographic_library.algorithm.symmetric;

import com.example.cryptographic_library.algorithm.encode.UTF_8;

import java.nio.ByteBuffer;
import java.util.Arrays;

public class RC6 {
    // 算法参数
    private static final int WORD_SIZE = 32;   // 字长（bits）
    private static final int ROUNDS = 20;      // 加密轮数
    private static final int KEY_LEN = 128;    // 密钥长度（bits）
    private static final int BLOCK_SIZE = 128; // 块大小（bits）
    private static final int BLOCK_BYTES = BLOCK_SIZE / 8;

    // 魔法常量
    private static final int P32 = 0xB7E15163;
    private static final int Q32 = 0x9E3779B9;

    private final int[] s; // 轮密钥数组

    public RC6(byte[] key) {
        validateKey(key);
        byte[] paddedKey = padKey(key);
        this.s = keySchedule(paddedKey);
    }

    private byte[] padKey(byte[] key) {
        if (key.length == KEY_LEN / 8) return key;

        // 确保密钥长度为 16 字节 (128 位)
        byte[] padded = new byte[KEY_LEN / 8];
        System.arraycopy(key, 0, padded, 0, Math.min(key.length, padded.length));
        return padded;
    }

    // 完整加密流程
    public byte[] encrypt(byte[] plaintext) {
        byte[] padded = pkcs7Pad(plaintext, BLOCK_BYTES);
        return processBlocks(padded, true);
    }

    // 完整解密流程
    public byte[] decrypt(byte[] ciphertext) {
        byte[] decrypted = processBlocks(ciphertext, false);
        return pkcs7Unpad(decrypted);
    }

    // PKCS7填充实现
    private byte[] pkcs7Pad(byte[] input, int blockSize) {
        int padding = blockSize - (input.length % blockSize);
        padding = padding == 0 ? blockSize : padding;
        byte[] padded = Arrays.copyOf(input, input.length + padding);
        Arrays.fill(padded, input.length, padded.length, (byte) padding);
        return padded;
    }

    // PKCS7去填充实现
    private byte[] pkcs7Unpad(byte[] input) {
        if (input.length == 0) throw new IllegalArgumentException("空输入");

        int padding = input[input.length - 1] & 0xFF;
        validatePadding(input, padding);

        return Arrays.copyOf(input, input.length - padding);
    }

    // 分组处理核心
    private byte[] processBlocks(byte[] input, boolean encrypt) {
        ByteBuffer output = ByteBuffer.allocate(input.length);

        for (int i = 0; i < input.length; i += BLOCK_BYTES) {
            byte[] block = Arrays.copyOfRange(input, i, i + BLOCK_BYTES);
            byte[] processed = encrypt ? encryptBlock(block) : decryptBlock(block);
            output.put(processed);
        }

        return output.array();
    }
    private void validateKey(byte[] key) {
        if (key == null || key.length == 0) {
            throw new IllegalArgumentException("密钥不能为空");
        }
        if (key.length > KEY_LEN / 8) {
            throw new IllegalArgumentException("密钥长度不能超过128位（16字节）");
        }
    }

    // 以下是RC6核心算法实现-----------------------------------------
    private int[] keySchedule(byte[] key) {
        // 确保密钥长度为16字节 (128位)
        if (key.length != KEY_LEN / 8) {
            throw new IllegalArgumentException("密钥必须是16字节");
        }
        
        // 以字(word)为单位处理密钥
        int c = KEY_LEN / 32; // c = 4 for 128-bit key
        int[] L = new int[c];
        
        // 将密钥字节转换为字数组 - 采用小端序转换，符合RC6标准
        for (int i = 0; i < c; i++) {
            L[i] = ((key[4*i] & 0xff)) |
                  ((key[4*i+1] & 0xff) << 8) |
                  ((key[4*i+2] & 0xff) << 16) |
                  ((key[4*i+3] & 0xff) << 24);
        }
        
        // 初始化轮密钥数组
        int t = 2 * ROUNDS + 4;
        int[] S = new int[t];
        S[0] = P32;
        
        // 按照RC6规范初始化S数组
        for (int i = 1; i < t; i++) {
            S[i] = S[i-1] + Q32;
        }
        
        // 混合密钥到轮密钥
        int A = 0, B = 0;
        int i = 0, j = 0;
        
        // 3倍的最大值确保充分混合
        int iterations = 3 * Math.max(c, t);
        
        for (int k = 0; k < iterations; k++) {
            // 一定要使用正确的位移运算，掩码确保位移值在有效范围内
            A = S[i] = rotateLeft((S[i] + A + B), 3);
            B = L[j] = rotateLeft((L[j] + A + B), (A + B) & 0x1f);
            i = (i + 1) % t;
            j = (j + 1) % c;
        }
        
        return S;
    }

    private byte[] encryptBlock(byte[] input) {
        validateBlock(input);
        int[] block = bytesToWords(input);
        int a = block[0], b = block[1], c = block[2], d = block[3];

        b += s[0];
        d += s[1];

        for (int r = 1; r <= ROUNDS; r++) {
            int t = rotateLeft((b * (2 * b + 1)), 5);
            int u = rotateLeft((d * (2 * d + 1)), 5);
            a = rotateLeft((a ^ t), u & 0x1f) + s[2 * r];
            c = rotateLeft((c ^ u), t & 0x1f) + s[2 * r + 1];

            int temp = a;
            a = b;
            b = c;
            c = d;
            d = temp;
        }

        a += s[2 * ROUNDS + 2];
        c += s[2 * ROUNDS + 3];

        block[0] = a;
        block[1] = b;
        block[2] = c;
        block[3] = d;
        
        return wordsToBytes(block);
    }

    private byte[] decryptBlock(byte[] input) {
        validateBlock(input);
        int[] block = bytesToWords(input);
        int a = block[0], b = block[1], c = block[2], d = block[3];

        c -= s[2 * ROUNDS + 3];
        a -= s[2 * ROUNDS + 2];

        for (int r = ROUNDS; r >= 1; r--) {
            int temp = d;
            d = c;
            c = b;
            b = a;
            a = temp;

            int u = rotateLeft((d * (2 * d + 1)), 5);
            int t = rotateLeft((b * (2 * b + 1)), 5);
            c = rotateRight((c - s[2 * r + 1]), t & 0x1f) ^ u;
            a = rotateRight((a - s[2 * r]), u & 0x1f) ^ t;
        }

        d -= s[1];
        b -= s[0];

        block[0] = a;
        block[1] = b;
        block[2] = c;
        block[3] = d;
        
        return wordsToBytes(block);
    }

    // 辅助方法---------------------------------------------------
    private void validateBlock(byte[] block) {
        if (block.length != BLOCK_BYTES) {
            throw new IllegalArgumentException("块必须为16字节");
        }
    }

    private void validatePadding(byte[] input, int padding) {
        if (padding < 1 || padding > BLOCK_BYTES) {
            throw new IllegalArgumentException("无效填充长度: " + padding);
        }

        for (int i = input.length - padding; i < input.length - 1; i++) {
            if (input[i] != padding) {
                throw new IllegalArgumentException("填充数据损坏");
            }
        }
    }

    private static int[] bytesToWords(byte[] bytes) {
        int[] words = new int[bytes.length / 4];
        // 使用小端序转换
        for (int i = 0; i < words.length; i++) {
            words[i] = ((bytes[i * 4] & 0xff)) |
                      ((bytes[i * 4 + 1] & 0xff) << 8) |
                      ((bytes[i * 4 + 2] & 0xff) << 16) |
                      ((bytes[i * 4 + 3] & 0xff) << 24);
        }
        return words;
    }

    private static byte[] wordsToBytes(int[] words) {
        byte[] bytes = new byte[words.length * 4];
        // 使用小端序转换
        for (int i = 0; i < words.length; i++) {
            bytes[i * 4] = (byte) (words[i] & 0xff);
            bytes[i * 4 + 1] = (byte) ((words[i] >> 8) & 0xff);
            bytes[i * 4 + 2] = (byte) ((words[i] >> 16) & 0xff);
            bytes[i * 4 + 3] = (byte) ((words[i] >> 24) & 0xff);
        }
        return bytes;
    }

    private static int rotateLeft(int value, int shift) {
        return (value << shift) | (value >>> (WORD_SIZE - shift));
    }

    private static int rotateRight(int value, int shift) {
        return (value >>> shift) | (value << (WORD_SIZE - shift));
    }

    /**
     * 使用已知测试向量验证RC6实现
     * @return 测试是否通过
     */
    public static boolean runTestVectors() {
        System.out.println("执行RC6已知答案测试...");
        boolean allPassed = true;
        
        // 测试向量1 - RC6官方测试向量
        try {
            System.out.println("\nTest Vector 1 - 官方测试向量");
            byte[] key1 = hexToBytes("00000000000000000000000000000000");
            byte[] plaintext1 = hexToBytes("00000000000000000000000000000000");
            // RC6官方验证结果 (来源: RC6规范文档)
            byte[] expected1 = hexToBytes("8FC3A53656B1F778C129DF4E9848A41E");
            
            RC6 rc6 = new RC6(key1);
            byte[] encrypted = rc6.encryptBlock(plaintext1);
            System.out.println("Plain: " + bytesToHex(plaintext1));
            System.out.println("Key: " + bytesToHex(key1));
            System.out.println("加密结果: " + bytesToHex(encrypted));
            System.out.println("预期结果: " + bytesToHex(expected1));
            
            boolean encryptMatch = Arrays.equals(encrypted, expected1);
            System.out.println("加密结果匹配: " + (encryptMatch ? "pass" : "fail"));
            
            byte[] decrypted = rc6.decryptBlock(encrypted);
            boolean decryptMatch = Arrays.equals(plaintext1, decrypted);
            System.out.println("解密结果匹配: " + (decryptMatch ? "pass" : "fail"));
            
            allPassed &= encryptMatch && decryptMatch;
            
            // 打印前几个S值帮助调试
            if (!encryptMatch) {
                System.out.println("\n轮密钥调试信息:");
                for (int i = 0; i < Math.min(8, rc6.s.length); i++) {
                    System.out.printf("S[%d] = 0x%08X\n", i, rc6.s[i]);
                }
            }
        } catch (Exception e) {
            System.out.println("测试向量1失败: " + e.getMessage());
            e.printStackTrace();
            allPassed = false;
        }
        
        // 测试向量2 - 使用另一个官方测试向量 (有些规范会提供多个测试向量)
        try {
            System.out.println("\nTest Vector 2 - 轮回测试");
            // 提供自定义测试数据，验证加密-解密轮回
            byte[] key2 = hexToBytes("0123456789ABCDEF0123456789ABCDEF");
            byte[] plaintext2 = hexToBytes("0123456789ABCDEF0123456789ABCDEF");
            
            RC6 rc6 = new RC6(key2);
            byte[] encrypted = rc6.encryptBlock(plaintext2);
            System.out.println("明文: " + bytesToHex(plaintext2));
            System.out.println("密钥: " + bytesToHex(key2));
            System.out.println("密文: " + bytesToHex(encrypted));
            
            // 使用轮回加密解密验证
            byte[] decrypted = rc6.decryptBlock(encrypted);
            System.out.println("解密: " + bytesToHex(decrypted));
            
            boolean roundTripMatch = Arrays.equals(plaintext2, decrypted);
            System.out.println("轮回匹配: " + (roundTripMatch ? "pass" : "fail"));
            
            allPassed &= roundTripMatch;
        } catch (Exception e) {
            System.out.println("测试向量2失败: " + e.getMessage());
            e.printStackTrace();
            allPassed = false;
        }
        
        // 测试向量3 - 另一组已知测试数据
        try {
            System.out.println("\nTest Vector 3 - 简单明文测试");
            byte[] key3 = hexToBytes("00000000000000000000000000000000");
            byte[] plaintext3 = hexToBytes("02132435465768798a9bacbdcedfe0f1");
            
            RC6 rc6 = new RC6(key3);
            byte[] encrypted = rc6.encryptBlock(plaintext3);
            System.out.println("明文: " + bytesToHex(plaintext3));
            System.out.println("密钥: " + bytesToHex(key3));
            System.out.println("密文: " + bytesToHex(encrypted));
            
            byte[] decrypted = rc6.decryptBlock(encrypted);
            boolean decryptMatch = Arrays.equals(plaintext3, decrypted);
            System.out.println("解密匹配: " + (decryptMatch ? "pass" : "fail"));
            
            allPassed &= decryptMatch;
        } catch (Exception e) {
            System.out.println("测试向量3失败: " + e.getMessage());
            e.printStackTrace();
            allPassed = false;
        }
        
        // 测试PKCS7填充
        try {
            System.out.println("\n测试PKCS#7填充");
            byte[] key4 = hexToBytes("0123456789ABCDEF0123456789ABCDEF");
            // 使用不是16字节倍数的明文
            byte[] plaintext4 = "This is a test for padding".getBytes();
            
            RC6 rc6 = new RC6(key4);
            byte[] encrypted = rc6.encrypt(plaintext4);
            byte[] decrypted = rc6.decrypt(encrypted);
            
            System.out.println("原始明文: " + new String(plaintext4));
            System.out.println("解密结果: " + new String(decrypted));
            
            boolean passed = Arrays.equals(plaintext4, decrypted);
            System.out.println("填充测试结果: " + (passed ? "pass" : "fail"));
            allPassed &= passed;
        } catch (Exception e) {
            System.out.println("填充测试失败: " + e.getMessage());
            e.printStackTrace();
            allPassed = false;
        }
        
        return allPassed;
    }
    
    /**
     * 十六进制字符串转字节数组
     */
    private static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                     + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }

    // 测试用例---------------------------------------------------
    public static void main(String[] args) {
        // 运行已知答案测试
        boolean testsPassed = runTestVectors();
        System.out.println("\n已知答案测试结果: " + (testsPassed ? "全部通过" : "测试失败"));
        System.out.println("\n------------------------");
        
        // 原示例代码
        byte[] key = UTF_8.encode("password");
        byte[] plaintext = UTF_8.encode("This is a test.");
        RC6 rc6 = new RC6(key);

        // 加密（自动填充到16 字节）
        byte[] ciphertext = rc6.encrypt(plaintext);
        System.out.println("加密结果（十六进制）: " + bytesToHex(ciphertext));

        // 解密（自动去填充）
        byte[] decrypted = rc6.decrypt(ciphertext);
        System.out.println("解密结果: " + UTF_8.decode(decrypted));
        System.out.println("对比结果: " + Arrays.equals(plaintext, decrypted));
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xFF));
        }
        return sb.toString();
    }
}

