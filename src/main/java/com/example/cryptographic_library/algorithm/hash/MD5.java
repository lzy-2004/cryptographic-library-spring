package com.example.cryptographic_library.algorithm.hash;

import com.example.cryptographic_library.algorithm.encode.UTF_8;

public class MD5 {
    private int[] state = new int[4]; // A, B, C, D
    private long bitCount; // 总比特数（原始消息）
    private byte[] buffer = new byte[64]; // 512-bit buffer
    private int bufferSize; // 当前字节数

    public MD5() {
        init();
    }

    private void init() {
        state[0] = 0x67452301;
        state[1] = 0xEFCDAB89;
        state[2] = 0x98BADCFE;
        state[3] = 0x10325476;
        bitCount = 0;
        bufferSize = 0;
    }

    public void update(byte[] input) {
        for (byte b : input) {
            buffer[bufferSize++] = b;
            bitCount += 8;
            if (bufferSize == 64) {
                processBlock(buffer, 0);
                bufferSize = 0;
            }
        }
    }

    private void processBlock(byte[] block, int offset) {
        int[] X = new int[16];
        for (int i = 0; i < 16; i++) {
            X[i] = byteArrayToInt(block, offset + i * 4);
        }

        int a = state[0], b = state[1], c = state[2], d = state[3];

        // Round 1
        a = FF(a, b, c, d, X[0], 7, 0xd76aa478);
        d = FF(d, a, b, c, X[1], 12, 0xe8c7b756);
        c = FF(c, d, a, b, X[2], 17, 0x242070db);
        b = FF(b, c, d, a, X[3], 22, 0xc1bdceee);
        a = FF(a, b, c, d, X[4], 7, 0xf57c0faf);
        d = FF(d, a, b, c, X[5], 12, 0x4787c62a);
        c = FF(c, d, a, b, X[6], 17, 0xa8304613);
        b = FF(b, c, d, a, X[7], 22, 0xfd469501);
        a = FF(a, b, c, d, X[8], 7, 0x698098d8);
        d = FF(d, a, b, c, X[9], 12, 0x8b44f7af);
        c = FF(c, d, a, b, X[10], 17, 0xffff5bb1);
        b = FF(b, c, d, a, X[11], 22, 0x895cd7be);
        a = FF(a, b, c, d, X[12], 7, 0x6b901122);
        d = FF(d, a, b, c, X[13], 12, 0xfd987193);
        c = FF(c, d, a, b, X[14], 17, 0xa679438e);
        b = FF(b, c, d, a, X[15], 22, 0x49b40821);

        // Round 2
        a = GG(a, b, c, d, X[1], 5, 0xf61e2562);
        d = GG(d, a, b, c, X[6], 9, 0xc040b340);
        c = GG(c, d, a, b, X[11], 14, 0x265e5a51);
        b = GG(b, c, d, a, X[0], 20, 0xe9b6c7aa);
        a = GG(a, b, c, d, X[5], 5, 0xd62f105d);
        d = GG(d, a, b, c, X[10], 9, 0x02441453);
        c = GG(c, d, a, b, X[15], 14, 0xd8a1e681);
        b = GG(b, c, d, a, X[4], 20, 0xe7d3fbc8);
        a = GG(a, b, c, d, X[9], 5, 0x21e1cde6);
        d = GG(d, a, b, c, X[14], 9, 0xc33707d6);
        c = GG(c, d, a, b, X[3], 14, 0xf4d50d87);
        b = GG(b, c, d, a, X[8], 20, 0x455a14ed);
        a = GG(a, b, c, d, X[13], 5, 0xa9e3e905);
        d = GG(d, a, b, c, X[2], 9, 0xfcefa3f8);
        c = GG(c, d, a, b, X[7], 14, 0x676f02d9);
        b = GG(b, c, d, a, X[12], 20, 0x8d2a4c8a);

        // Round 3
        a = HH(a, b, c, d, X[5], 4, 0xfffa3942);
        d = HH(d, a, b, c, X[8], 11, 0x8771f681);
        c = HH(c, d, a, b, X[11], 16, 0x6d9d6122);
        b = HH(b, c, d, a, X[14], 23, 0xfde5380c);
        a = HH(a, b, c, d, X[1], 4, 0xa4beea44);
        d = HH(d, a, b, c, X[4], 11, 0x4bdecfa9);
        c = HH(c, d, a, b, X[7], 16, 0xf6bb4b60);
        b = HH(b, c, d, a, X[10], 23, 0xbebfbc70);
        a = HH(a, b, c, d, X[13], 4, 0x289b7ec6);
        d = HH(d, a, b, c, X[0], 11, 0xeaa127fa);
        c = HH(c, d, a, b, X[3], 16, 0xd4ef3085);
        b = HH(b, c, d, a, X[6], 23, 0x04881d05);
        a = HH(a, b, c, d, X[9], 4, 0xd9d4d039);
        d = HH(d, a, b, c, X[12], 11, 0xe6db99e5);
        c = HH(c, d, a, b, X[15], 16, 0x1fa27cf8);
        b = HH(b, c, d, a, X[2], 23, 0xc4ac5665);

        // Round 4
        a = II(a, b, c, d, X[0], 6, 0xf4292244);
        d = II(d, a, b, c, X[7], 10, 0x432aff97);
        c = II(c, d, a, b, X[14], 15, 0xab9423a7);
        b = II(b, c, d, a, X[5], 21, 0xfc93a039);
        a = II(a, b, c, d, X[12], 6, 0x655b59c3);
        d = II(d, a, b, c, X[3], 10, 0x8f0ccc92);
        c = II(c, d, a, b, X[10], 15, 0xffeff47d);
        b = II(b, c, d, a, X[1], 21, 0x85845dd1);
        a = II(a, b, c, d, X[8], 6, 0x6fa87e4f);
        d = II(d, a, b, c, X[15], 10, 0xfe2ce6e0);
        c = II(c, d, a, b, X[6], 15, 0xa3014314);
        b = II(b, c, d, a, X[13], 21, 0x4e0811a1);
        a = II(a, b, c, d, X[4], 6, 0xf7537e82);
        d = II(d, a, b, c, X[11], 10, 0xbd3af235);
        c = II(c, d, a, b, X[2], 15, 0x2ad7d2bb);
        b = II(b, c, d, a, X[9], 21, 0xeb86d391);

        state[0] += a;
        state[1] += b;
        state[2] += c;
        state[3] += d;
    }

    // 辅助函数：FF, GG, HH, II 实现各轮的基本操作
    private int FF(int a, int b, int c, int d, int x, int s, int t) {
        a += (b & c) | (~b & d);
        a += x + t;
        a = Integer.rotateLeft(a, s);
        a += b;
        return a;
    }

    private int GG(int a, int b, int c, int d, int x, int s, int t) {
        a += (b & d) | (c & ~d);
        a += x + t;
        a = Integer.rotateLeft(a, s);
        a += b;
        return a;
    }

    private int HH(int a, int b, int c, int d, int x, int s, int t) {
        a += b ^ c ^ d;
        a += x + t;
        a = Integer.rotateLeft(a, s);
        a += b;
        return a;
    }

    private int II(int a, int b, int c, int d, int x, int s, int t) {
        a += c ^ (b | ~d);
        a += x + t;
        a = Integer.rotateLeft(a, s);
        a += b;
        return a;
    }

    public byte[] digest() {
        long originalBitCount = bitCount;

        // 添加填充位 0x80
        buffer[bufferSize++] = (byte) 0x80;
        if (bufferSize > 56) {
            // 填充当前块并处理
            while (bufferSize < 64) {
                buffer[bufferSize++] = 0;
            }
            processBlock(buffer, 0);
            bufferSize = 0;
        }

        // 填充0到总长度 ≡ 56 mod 64
        while (bufferSize < 56) {
            buffer[bufferSize++] = 0;
        }

        // 添加原始消息长度的低64位（小端序）
        for (int i = 0; i < 8; i++) {
            buffer[56 + i] = (byte) (originalBitCount >>> (i * 8));
        }
        processBlock(buffer, 0);

        // 生成结果
        byte[] result = new byte[16];
        for (int i = 0; i < 4; i++) {
            int stateVal = state[i];
            result[i * 4] = (byte) (stateVal & 0xFF);
            result[i * 4 + 1] = (byte) ((stateVal >> 8) & 0xFF);
            result[i * 4 + 2] = (byte) ((stateVal >> 16) & 0xFF);
            result[i * 4 + 3] = (byte) ((stateVal >> 24) & 0xFF);
        }

        // 重置状态
        init();

        return result;
    }

    private int byteArrayToInt(byte[] bytes, int offset) {
        return (bytes[offset] & 0xFF)
                | ((bytes[offset + 1] & 0xFF) << 8)
                | ((bytes[offset + 2] & 0xFF) << 16)
                | ((bytes[offset + 3] & 0xFF) << 24);
    }

    public static void main(String[] args) {
        String input = "";
        MD5 md5 = new MD5();
        md5.update(UTF_8.encode(input));
        byte[] hash = md5.digest();

        StringBuilder hexString = new StringBuilder();
        for (byte b : hash) {
            String hex = Integer.toHexString(0xFF & b);
            if (hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }

        System.out.println("Input: " + input);
        System.out.println("MD5 Hash: " + hexString.toString());
    }
}