package com.example.cryptographic_library.algorithm.hash;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class RIPEMD160 {
    private static final int BLOCK_SIZE = 64; // 512-bit blocks
    private static final int[] INIT_STATE = {
            0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0
    };

    private int[] state;
    private long count;
    private byte[] buffer;

    public RIPEMD160() {
        reset();
    }

    public void update(byte[] input) {
        int index = 0;
        int remaining = input.length;
        int bufferSpace = BLOCK_SIZE - (int) (count % BLOCK_SIZE);

        count += remaining;

        if (bufferSpace > remaining) {
            System.arraycopy(input, 0, buffer, BLOCK_SIZE - bufferSpace, remaining);
            return;
        }

        System.arraycopy(input, 0, buffer, BLOCK_SIZE - bufferSpace, bufferSpace);
        processBlock(buffer, 0);
        index += bufferSpace;
        remaining -= bufferSpace;

        while (remaining >= BLOCK_SIZE) {
            processBlock(input, index);
            index += BLOCK_SIZE;
            remaining -= BLOCK_SIZE;
        }

        System.arraycopy(input, index, buffer, 0, remaining);
    }

    public byte[] digest() {
        byte[] padding = padMessage();
        update(padding);

        ByteBuffer bb = ByteBuffer.allocate(20)
                .order(ByteOrder.LITTLE_ENDIAN);
        for (int s : state) {
            bb.putInt(s);
        }

        byte[] digest = bb.array();
        reset();
        return digest;
    }

    private void reset() {
        state = INIT_STATE.clone();
        count = 0;
        buffer = new byte[BLOCK_SIZE];
    }

    private byte[] padMessage() {
        int padLength = (int) (count % BLOCK_SIZE);
        padLength = (padLength < 56) ?
                56 - padLength :
                120 - padLength;

        byte[] pad = new byte[padLength + 8];
        pad[0] = (byte) 0x80;

        long bitLength = count << 3;
        for (int i = 0; i < 8; i++) {
            pad[pad.length - 8 + i] = (byte) (bitLength >>> (i * 8));
        }

        return pad;
    }

    private void processBlock(byte[] block, int offset) {
        int[] X = new int[16];
        ByteBuffer.wrap(block, offset, BLOCK_SIZE)
                .order(ByteOrder.LITTLE_ENDIAN)
                .asIntBuffer()
                .get(X);

        int A1 = state[0], B1 = state[1], C1 = state[2], D1 = state[3], E1 = state[4];
        int A2 = state[0], B2 = state[1], C2 = state[2], D2 = state[3], E2 = state[4];

        for (int i = 0; i < 80; i++) {
            int phase = i / 16;
            int T1, T2;

            // 左通道处理
            switch (phase) {
                case 0:
                    T1 = A1 + f1(B1, C1, D1) + X[r1[i]] + K1[phase];
                    break;
                case 1:
                    T1 = A1 + f2(B1, C1, D1) + X[r1[i]] + K1[phase];
                    break;
                case 2:
                    T1 = A1 + f3(B1, C1, D1) + X[r1[i]] + K1[phase];
                    break;
                case 3:
                    T1 = A1 + f4(B1, C1, D1) + X[r1[i]] + K1[phase];
                    break;
                default:
                    T1 = A1 + f5(B1, C1, D1) + X[r1[i]] + K1[phase];
            }
            T1 = Integer.rotateLeft(T1, s1[i]) + E1;

            // 更新左通道变量
            int temp1 = E1;
            E1 = D1;
            D1 = Integer.rotateLeft(C1, 10);
            C1 = B1;
            B1 = T1;
            A1 = temp1;

            // 右通道处理
            switch (phase) {
                case 0:
                    T2 = A2 + f5(B2, C2, D2) + X[r2[i]] + K2[phase];
                    break;
                case 1:
                    T2 = A2 + f4(B2, C2, D2) + X[r2[i]] + K2[phase];
                    break;
                case 2:
                    T2 = A2 + f3(B2, C2, D2) + X[r2[i]] + K2[phase];
                    break;
                case 3:
                    T2 = A2 + f2(B2, C2, D2) + X[r2[i]] + K2[phase];
                    break;
                default:
                    T2 = A2 + f1(B2, C2, D2) + X[r2[i]] + K2[phase];
            }
            T2 = Integer.rotateLeft(T2, s2[i]) + E2;

            // 更新右通道变量
            int temp2 = E2;
            E2 = D2;
            D2 = Integer.rotateLeft(C2, 10);
            C2 = B2;
            B2 = T2;
            A2 = temp2;
        }

        // 合并结果
        int[] temp = {
                state[1] + C1 + D2,
                state[2] + D1 + E2,
                state[3] + E1 + A2,
                state[4] + A1 + B2,
                state[0] + B1 + C2
        };
        System.arraycopy(temp, 0, state, 0, 5);
    }


    // 轮函数定义
    private static int f1(int x, int y, int z) { return x ^ y ^ z; }
    private static int f2(int x, int y, int z) { return (x & y) | (~x & z); }
    private static int f3(int x, int y, int z) { return (x | ~y) ^ z; }
    private static int f4(int x, int y, int z) { return (x & z) | (y & ~z); }
    private static int f5(int x, int y, int z) { return x ^ (y | ~z); }

    // 轮次参数
    private static final int[] r1 = {
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
            7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
            3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
            1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
            4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13
    };

    private static final int[] r2 = {
            5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
            6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
            15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
            8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
            12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11
    };

    private static final int[] s1 = {
            11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
            7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
            11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
            11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
            9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6
    };

    private static final int[] s2 = {
            8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
            9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
            9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
            15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
            8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11
    };

    private static final int[] K1 = {
            0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E
    };

    private static final int[] K2 = {
            0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000
    };

    // 测试用例
    public static void main(String[] args) {
        // 空字符串测试
        RIPEMD160 md = new RIPEMD160();
        System.out.println("空字符串: " + bytesToHex(md.digest()));
        // 应输出：9c1185a5c5e9fc54612808977ee8f548b2258d31

        // "abc"测试
        md.update("abc".getBytes());
        System.out.println("'abc': " + bytesToHex(md.digest()));
        // 应输出：8eb208f7e05d987a9b044a8e98c6b087f15a0bfc
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xFF));
        }
        return sb.toString();
    }
}
