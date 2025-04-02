package com.example.cryptographic_library.algorithm.hash;

import java.util.Arrays;

public class SHA3_512 {
    // 算法参数 (SHA3-512)
    private static final int BITRATE = 576;     // 72 字节块大小
    private static final int CAPACITY = 1024;   // 容量
    private static final int OUTPUT_LENGTH = 64; // 输出字节数（512位）
    private static final int ROUNDS = 24;       // Keccak轮数

    // 轮常量表（24个64位常量）
    private static final long[] RC = {
            0x0000000000000001L, 0x0000000000008082L, 0x800000000000808aL,
            0x8000000080008000L, 0x000000000000808bL, 0x0000000080000001L,
            0x8000000080008081L, 0x8000000000008009L, 0x000000000000008aL,
            0x0000000000000088L, 0x0000000080008009L, 0x000000008000000aL,
            0x000000008000808bL, 0x800000000000008bL, 0x8000000000008089L,
            0x8000000000008003L, 0x8000000000008002L, 0x8000000000000080L,
            0x000000000000800aL, 0x800000008000000aL, 0x8000000080008081L,
            0x8000000000008080L, 0x0000000080000001L, 0x8000000080008008L
    };

    public static byte[] hash(byte[] input) {
        long[] state = new long[25]; // 5x5状态数组（每个元素64位）

        // 1. 消息填充
        byte[] padded = pad(input);

        // 2. 吸收阶段
        for (int offset = 0; offset < padded.length; offset += BITRATE / 8) {
            absorbBlock(padded, offset, state);
            keccakF(state); // 应用Keccak-f置换
        }

        // 3. 挤压阶段（直接取前64字节）
        return squeeze(state);
    }

    // SHA3-512专用填充规则
    private static byte[] pad(byte[] input) {
        int blockSize = BITRATE / 8; // 72字节
        int q = blockSize - (input.length % blockSize);

        // 填充规则：0x06 + 0x00* + 0x80
        byte[] padded = Arrays.copyOf(input, input.length + (q == 1 ? blockSize : q));
        padded[input.length] = 0x06; // 关键修正：使用0x06而不是0x01
        padded[padded.length - 1] = (byte) 0x80;

        return padded;
    }

    // 吸收单个块（72字节）
    private static void absorbBlock(byte[] block, int offset, long[] state) {
        for (int i = 0; i < BITRATE / 64; i++) {
            state[i] ^= toLane(block, offset + i * 8);
        }
    }

    // Keccak-f[1600]置换
    private static void keccakF(long[] state) {
        for (int round = 0; round < ROUNDS; round++) {
            theta(state);
            rhoPi(state);
            chi(state);
            iota(state, round);
        }
    }

    // θ步骤（使用异或操作）
    private static void theta(long[] a) {
        long[] c = new long[5];
        for (int x = 0; x < 5; x++) {
            c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
        }

        long[] d = new long[5];
        for (int x = 0; x < 5; x++) {
            int prev = (x + 4) % 5; // x-1 mod5
            int next = (x + 1) % 5;
            d[x] = c[prev] ^ Long.rotateLeft(c[next], 1); // 关键修正：使用异或
        }

        for (int i = 0; i < 25; i++) {
            a[i] ^= d[i % 5]; // 关键修正：使用异或
        }
    }

    // ρ和π步骤合并实现
    private static void rhoPi(long[] a) {
        long[] temp = new long[25];
        System.arraycopy(a, 0, temp, 0, 25);

        int[] rotations = {
                0, 1, 62, 28, 27,
                36, 44, 6, 55, 20,
                3, 10, 43, 25, 39,
                41, 45, 15, 21, 8,
                18, 2, 61, 56, 14
        };

        for (int i = 0; i < 25; i++) {
            int x = i % 5;
            int y = i / 5;
            int newIndex = (2 * x + 3 * y) % 5 * 5 + y;
            a[newIndex] = Long.rotateLeft(temp[i], rotations[i]);
        }
    }

    // χ步骤
    private static void chi(long[] a) {
        long[] temp = Arrays.copyOf(a, 25);
        for (int i = 0; i < 25; i++) {
            int y = i / 5;
            int x = i % 5;
            a[i] = temp[i] ^ (~temp[y * 5 + (x + 1) % 5] & temp[y * 5 + (x + 2) % 5]);
        }
    }

    // ι步骤（应用轮常量）
    private static void iota(long[] a, int round) {
        a[0] ^= RC[round];
    }

    // 挤压输出（取前64字节）
    private static byte[] squeeze(long[] state) {
        byte[] output = new byte[OUTPUT_LENGTH];
        for (int i = 0; i < OUTPUT_LENGTH; i += 8) {
            fromLane(state[i / 8], output, i);
        }
        return output;
    }

    // 小端字节序解码（8字节转long）
    private static long toLane(byte[] bytes, int offset) {
        long value = 0;
        for (int i = 0; i < 8; i++) {
            value |= (bytes[offset + i] & 0xFFL) << (i * 8);
        }
        return value;
    }

    // 小端字节序编码（long转8字节）
    private static void fromLane(long value, byte[] out, int offset) {
        for (int i = 0; i < 8; i++) {
            out[offset + i] = (byte) (value >> (i * 8));
        }
    }

    // 测试用例
    public static void main(String[] args) {
        test("", "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26");
    }

    private static void test(String input, String expected) {
        byte[] hash = hash(input.getBytes());
        String actual = toHex(hash);
        System.out.println("输入: \"" + input + "\"");
        System.out.println("计算值: " + actual);
        System.out.println("期望值: " + expected);
        System.out.println("结果: " + (actual.equals(expected) ? "通过" : "失败"));
        System.out.println();
    }

    private static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xFF));
        }
        return sb.toString();
    }
}