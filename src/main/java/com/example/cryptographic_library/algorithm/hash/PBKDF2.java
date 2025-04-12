package com.example.cryptographic_library.algorithm.hash;

import com.example.cryptographic_library.algorithm.encode.UTF_8;

import java.util.Arrays;

public class PBKDF2 {
    private static final int MAX_DERIVED_KEY_LENGTH = Integer.MAX_VALUE - 1;
    private static final int HMAC_OUTPUT_SIZE = HMacSHA256.OUTPUT_SIZE;

    public static byte[] deriveKey(char[] password,
                                   byte[] salt,
                                   int iterations,
                                   int keyLength) {
        validateParameters(password, salt, iterations, keyLength);
        HMacSHA256 hmac = new HMacSHA256(toBytes(password));
        int blockCount = (int) Math.ceil((double) keyLength / HMAC_OUTPUT_SIZE);
        byte[] derivedKey = new byte[blockCount * HMAC_OUTPUT_SIZE];

        for (int i = 1; i <= blockCount; i++) {
            processBlock(hmac, salt, iterations, i, derivedKey, (i-1)*HMAC_OUTPUT_SIZE);
        }
        return Arrays.copyOf(derivedKey, keyLength);
    }

    private static void processBlock(HMacSHA256 hmac,
                                     byte[] salt,
                                     int iterations,
                                     int blockIndex,
                                     byte[] dest,
                                     int destOffset) {
        byte[] block = new byte[salt.length + 4];
        System.arraycopy(salt, 0, block, 0, salt.length);
        writeIntBE(blockIndex, block, salt.length);
        byte[] u = hmac.compute(block);
        byte[] result = Arrays.copyOf(u, u.length);
        for (int j = 1; j <= iterations; j++) {
            if (j > 1) {
                u = hmac.compute(u);
                xorBytes(result, u);
            }
        }
        System.arraycopy(result, 0, dest, destOffset, result.length);
    }

    // 保持UTF-8编码转换
    private static byte[] toBytes(char[] chars) {
        return UTF_8.encode(new String(chars));
    }

    // 辅助方法 -------------------------------------------------
    private static void validateParameters(char[] password,
                                           byte[] salt,
                                           int iterations,
                                           int keyLength) {
        if (password == null ) {
            throw new IllegalArgumentException("Password cannot be empty");
        }
        if (salt == null ) {
            throw new IllegalArgumentException("Salt cannot be empty");
        }
        if (iterations < 1) {
            throw new IllegalArgumentException("Iterations must be positive");
        }
        if (keyLength < 1 || keyLength > MAX_DERIVED_KEY_LENGTH) {
            throw new IllegalArgumentException("Invalid key length");
        }
    }
    private static void writeIntBE(int value, byte[] dest, int offset) {
        dest[offset] = (byte) (value >> 24);
        dest[offset+1] = (byte) (value >> 16);
        dest[offset+2] = (byte) (value >> 8);
        dest[offset+3] = (byte) value;
    }

    private static void xorBytes(byte[] a, byte[] b) {
        for (int i = 0; i < a.length; i++) {
            a[i] ^= b[i];
        }
    }

    // 更新测试用例为SHA-256的测试向量
    public static void main(String[] args) {
        // 使用NIST官方测试向量示例（需替换实际测试参数）
        char[] password = "password".toCharArray();
        byte[] salt = UTF_8.encode("salt");
        int iterations = 1;
        int keyLength = 16;

        byte[] key = deriveKey(password, salt, iterations, keyLength);
        System.out.println("PBKDF2-HMAC-SHA256: " + bytesToHex(key));
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xFF));
        }
        return sb.toString();
    }
}

