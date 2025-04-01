package com.example.cryptographic_library.algorithm.hash;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class SHA256 {
    // 初始哈希值（前8个质数的平方根小数部分前32位）
    private static final int[] INIT_HASH = {
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    // 常量（前64个质数的立方根小数部分前32位）
    private static final int[] K = {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
            0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
            0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
            0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
            0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
            0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
            0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
            0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
            0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    public static byte[] hash(byte[] message) {
        // 消息填充
        byte[] padded = padMessage(message);

        // 初始化哈希值
        int[] hash = INIT_HASH.clone();

        // 分块处理
        for (int i = 0; i < padded.length; i += 64) {
            processBlock(padded, i, hash);
        }

        return toByteArray(hash);
    }

    // 消息填充（512位分组）
    private static byte[] padMessage(byte[] message) {
        int originalBits = message.length * 8;
        int paddingBits = (512 - (originalBits % 512 + 65)) % 512;

        byte[] padded = new byte[(originalBits + 1 + paddingBits + 64) / 8];
        System.arraycopy(message, 0, padded, 0, message.length);
        padded[message.length] = (byte)0x80; // 添加结束位

        // 添加长度信息（64位大端）
        ByteBuffer.wrap(padded)
                .position(padded.length - 8)
                .putLong(originalBits);

        return padded;
    }

    // 处理单个512位块
    private static void processBlock(byte[] block, int offset, int[] hash) {
        int[] w = new int[64];
        ByteBuffer buffer = ByteBuffer.wrap(block, offset, 64)
                .order(ByteOrder.BIG_ENDIAN);

        // 前16个字
        for (int i = 0; i < 16; i++) {
            w[i] = buffer.getInt();
        }

        // 扩展剩余字
        for (int i = 16; i < 64; i++) {
            int s0 = rotr(w[i-15], 7) ^ rotr(w[i-15], 18) ^ (w[i-15] >>> 3);
            int s1 = rotr(w[i-2], 17) ^ rotr(w[i-2], 19) ^ (w[i-2] >>> 10);
            w[i] = w[i-16] + s0 + w[i-7] + s1;
        }

        // 初始化工作变量
        int a = hash[0];
        int b = hash[1];
        int c = hash[2];
        int d = hash[3];
        int e = hash[4];
        int f = hash[5];
        int g = hash[6];
        int h = hash[7];

        // 主循环
        for (int i = 0; i < 64; i++) {
            int S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            int ch = (e & f) ^ (~e & g);
            int temp1 = h + S1 + ch + K[i] + w[i];
            int S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            int maj = (a & b) ^ (a & c) ^ (b & c);
            int temp2 = S0 + maj;

            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        // 更新哈希值
        hash[0] += a;
        hash[1] += b;
        hash[2] += c;
        hash[3] += d;
        hash[4] += e;
        hash[5] += f;
        hash[6] += g;
        hash[7] += h;
    }

    // 辅助方法：循环右移
    private static int rotr(int value, int bits) {
        return (value >>> bits) | (value << (32 - bits));
    }

    // 将哈希值转为字节数组
    private static byte[] toByteArray(int[] hash) {
        ByteBuffer buffer = ByteBuffer.allocate(32)
                .order(ByteOrder.BIG_ENDIAN);
        for (int h : hash) {
            buffer.putInt(h);
        }
        return buffer.array();
    }

    // 测试用例
    public static void main(String[] args) {
        test("", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        test("abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        test("hello world", "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");
    }

    private static void test(String input, String expected) {
        byte[] hash = hash(input.getBytes());
        String actual = bytesToHex(hash);
        System.out.println("输入: \"" + input + "\"");
        System.out.println("计算值: " + actual);
        System.out.println("期望值: " + expected);
        System.out.println("结果: " + (actual.equals(expected) ? "通过" : "失败"));
        System.out.println();
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xFF));
        }
        return sb.toString();
    }
}

