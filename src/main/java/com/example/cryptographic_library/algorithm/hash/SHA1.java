package com.example.cryptographic_library.algorithm.hash;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class SHA1 {
    // 常量定义
    private static final int[] K = {
            0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6
    };

    // 初始哈希值
    private static final int H0 = 0x67452301;
    private static final int H1 = 0xEFCDAB89;
    private static final int H2 = 0x98BADCFE;
    private static final int H3 = 0x10325476;
    private static final int H4 = 0xC3D2E1F0;

    public static byte[] hash(byte[] message) {
        // 消息填充
        byte[] padded = padMessage(message);

        // 初始化哈希值
        int h0 = H0;
        int h1 = H1;
        int h2 = H2;
        int h3 = H3;
        int h4 = H4;

        // 分块处理
        for (int i = 0; i < padded.length; i += 64) {
            int[] words = processBlock(padded, i);

            // 初始化工作变量
            int a = h0;
            int b = h1;
            int c = h2;
            int d = h3;
            int e = h4;

            // 主循环
            for (int t = 0; t < 80; t++) {
                int temp = Integer.rotateLeft(a, 5) + f(t, b, c, d) + e + words[t] + K[t/20];
                e = d;
                d = c;
                c = Integer.rotateLeft(b, 30);
                b = a;
                a = temp;
            }

            // 更新哈希值
            h0 += a;
            h1 += b;
            h2 += c;
            h3 += d;
            h4 += e;
        }

        return toByteArray(h0, h1, h2, h3, h4);
    }

    // 消息填充方法
    private static byte[] padMessage(byte[] message) {
        int originalBits = message.length * 8;
        int paddingBits = (448 - (originalBits + 1) % 512) % 512;

        byte[] padded = new byte[(originalBits + 1 + paddingBits + 64) / 8];
        System.arraycopy(message, 0, padded, 0, message.length);
        padded[message.length] = (byte)0x80; // 添加1的二进制位

        // 添加长度信息（64位大端）
        ByteBuffer.wrap(padded)
                .position(padded.length - 8)
                .putLong(originalBits);

        return padded;
    }

    // 处理512位块
    private static int[] processBlock(byte[] block, int offset) {
        int[] words = new int[80];

        // 初始16个字
        ByteBuffer buffer = ByteBuffer.wrap(block, offset, 64)
                .order(ByteOrder.BIG_ENDIAN);
        for (int i = 0; i < 16; i++) {
            words[i] = buffer.getInt();
        }

        // 扩展剩余字
        for (int i = 16; i < 80; i++) {
            words[i] = Integer.rotateLeft(
                    words[i-3] ^ words[i-8] ^ words[i-14] ^ words[i-16], 1
            );
        }
        return words;
    }

    // 逻辑函数
    private static int f(int t, int b, int c, int d) {
        if (t < 20) return (b & c) | ((~b) & d);
        if (t < 40) return b ^ c ^ d;
        if (t < 60) return (b & c) | (b & d) | (c & d);
        return b ^ c ^ d;
    }

    // 将哈希值转为字节数组
    private static byte[] toByteArray(int h0, int h1, int h2, int h3, int h4) {
        ByteBuffer buffer = ByteBuffer.allocate(20)
                .order(ByteOrder.BIG_ENDIAN)
                .putInt(h0)
                .putInt(h1)
                .putInt(h2)
                .putInt(h3)
                .putInt(h4);
        return buffer.array();
    }

    // 测试用例
    public static void main(String[] args) {
        test("", "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        test("The quick brown fox jumps over the lazy dog", "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12");
        test("abc", "a9993e364706816aba3e25717850c26c9cd0d89d");
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

