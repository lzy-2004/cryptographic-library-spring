package com.example.cryptographic_library.algorithm.hash;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class HMacSHA256 {
    public static final int OUTPUT_SIZE = 32;
    private static final int BLOCK_SIZE = 64; // SHA-256的块大小（字节）
    private static final byte IPAD = 0x36;
    private static final byte OPAD = 0x5C;

    private final byte[] secretKey;

    public HMacSHA256(byte[] key) {
        // 标准化处理密钥
        if (key.length > BLOCK_SIZE) {
            this.secretKey = sha256(key); // 长密钥哈希压缩
        } else {
            this.secretKey = Arrays.copyOf(key, BLOCK_SIZE); // 短密钥补零
        }
    }

    public byte[] compute(byte[] message) {
        // 生成内外部填充密钥
        byte[] ipadKey = xorBytes(secretKey, IPAD);
        byte[] opadKey = xorBytes(secretKey, OPAD);

        // 计算内部哈希
        byte[] innerHash = sha256(concat(ipadKey, message));

        // 计算最终HMAC
        return sha256(concat(opadKey, innerHash));
    }

    // 辅助方法 -------------------------------------------------
    private static byte[] xorBytes(byte[] data, byte value) {
        byte[] result = new byte[data.length];
        for (int i = 0; i < data.length; i++) {
            result[i] = (byte) (data[i] ^ value);
        }
        return result;
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] combined = new byte[a.length + b.length];
        System.arraycopy(a, 0, combined, 0, a.length);
        System.arraycopy(b, 0, combined, a.length, b.length);
        return combined;
    }

    private static byte[] sha256(byte[] input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return md.digest(input);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not found", e);
        }
    }

    // 测试用例 -------------------------------------------------
    public static void main(String[] args) {
        // 测试用例1：RFC 4231 Test Case 1
        byte[] key = "Jefe".getBytes();
        byte[] message = "what do ya want for nothing?".getBytes();

        HMacSHA256 hmac = new HMacSHA256(key);
        byte[] result = hmac.compute(message);

        System.out.println("HMAC-SHA256: " + bytesToHex(result));
        // 正确结果：5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
