package com.example.cryptographic_library.algorithm.hash;

import com.example.cryptographic_library.algorithm.encode.UTF_8;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class HMacSHA1 {
    private static final int BLOCK_SIZE = 64; // SHA-1块大小（字节）
    private static final byte IPAD = 0x36;
    private static final byte OPAD = 0x5C;

    private final byte[] secretKey;
    private final MessageDigest md;

    public HMacSHA1(byte[] key) {
        this.secretKey = processKey(key);
        this.md = getSha1Digest();
    }

    // 密钥预处理
    private byte[] processKey(byte[] key) {
        if (key.length > BLOCK_SIZE) {
            // 密钥过长时先进行SHA-1哈希
            key = sha1(key);
        }
        if (key.length < BLOCK_SIZE) {
            // 密钥过短时补零
            byte[] paddedKey = new byte[BLOCK_SIZE];
            System.arraycopy(key, 0, paddedKey, 0, key.length);
            return paddedKey;
        }
        return Arrays.copyOf(key, key.length);
    }

    // 计算HMAC值
    public byte[] calculate(byte[] message) {
        // 内部哈希：H(K ⊕ ipad || message)
        byte[] innerHash = sha1(xorPad(secretKey, IPAD), message);

        // 外部哈希：H(K ⊕ opad || innerHash)
        return sha1(xorPad(secretKey, OPAD), innerHash);
    }

    // 带密钥前缀的SHA-1计算
    private byte[] sha1(byte[] prefix, byte[] data) {
        md.reset();
        md.update(prefix);
        md.update(data);
        return md.digest();
    }

    // 单参数SHA-1
    private static byte[] sha1(byte[] data) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            return md.digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-1算法不可用", e);
        }
    }

    // 生成填充后的密钥
    private byte[] xorPad(byte[] key, byte pad) {
        byte[] result = new byte[BLOCK_SIZE];
        for (int i = 0; i < BLOCK_SIZE; i++) {
            result[i] = (byte) (key[i] ^ pad);
        }
        return result;
    }

    // 获取SHA-1实例
    private MessageDigest getSha1Digest() {
        try {
            return MessageDigest.getInstance("SHA-1");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-1算法不可用", e);
        }
    }

    // 测试用例（符合RFC 2202标准）
    public static void main(String[] args) {
        // 测试用例1
        byte[] key1 = hexToBytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        byte[] data1 = UTF_8.encode("Hi There");
        String expected1 = "b617318655057264e28bc0b6fb378c8ef146be00";

        HMacSHA1 hmac1 = new HMacSHA1(key1);
        String actual1 = bytesToHex(hmac1.calculate(data1));
        System.out.println("测试用例1: " + (expected1.equals(actual1) ? "通过" : "失败"));

        // 测试用例2（长密钥）
        byte[] key2 = UTF_8.encode("Jefe");
        byte[] data2 = UTF_8.encode("what do ya want for nothing?");
        String expected2 = "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79";

        HMacSHA1 hmac2 = new HMacSHA1(key2);
        String actual2 = bytesToHex(hmac2.calculate(data2));
        System.out.println("测试用例2: " + (expected2.equals(actual2) ? "通过" : "失败"));
    }

    // 十六进制转换工具
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }
}
