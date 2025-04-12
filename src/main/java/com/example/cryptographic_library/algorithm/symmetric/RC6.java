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
        if (key.length == BLOCK_BYTES) return key;

        byte[] padded = new byte[BLOCK_BYTES];
        System.arraycopy(key, 0, padded, 0, key.length);
        int padding = BLOCK_BYTES - key.length;
        Arrays.fill(padded, key.length, BLOCK_BYTES, (byte) padding);
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
        if (key.length > KEY_LEN / 8) {
            throw new IllegalArgumentException("密钥长度不能超过128位（16字节）");
        }
    }

    // 以下是RC6核心算法实现-----------------------------------------
    private int[] keySchedule(byte[] key) {
        int c = key.length / 4;
        int[] l = new int[c];
        ByteBuffer.wrap(key).asIntBuffer().get(l);

        int t = 2 * ROUNDS + 4;
        int[] s = new int[t];
        s[0] = P32;

        for (int i = 1; i < t; i++) {
            s[i] = s[i - 1] + Q32;
        }

        int a = 0, b = 0;
        int i = 0, j = 0;
        int v = 3 * Math.max(c, t);

        for (int k = 0; k < v; k++) {
            s[i] = rotateLeft(s[i] + a + b, 3);
            a = s[i];
            l[j] = rotateLeft(l[j] + a + b, a + b);
            b = l[j];
            i = (i + 1) % t;
            j = (j + 1) % c;
        }

        return s;
    }

    private byte[] encryptBlock(byte[] input) {
        validateBlock(input);
        int[] block = bytesToWords(input);
        int a = block[0], b = block[1], c = block[2], d = block[3];

        b += s[0];
        d += s[1];

        for (int r = 1; r <= ROUNDS; r++) {
            int t = rotateLeft(b * (2 * b + 1), 5);
            int u = rotateLeft(d * (2 * d + 1), 5);
            a = rotateLeft(a ^ t, u) + s[2 * r];
            c = rotateLeft(c ^ u, t) + s[2 * r + 1];

            int temp = a;
            a = b;
            b = c;
            c = d;
            d = temp;
        }

        a += s[2 * ROUNDS + 2];
        c += s[2 * ROUNDS + 3];

        return wordsToBytes(new int[]{a, b, c, d});
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

            int u = rotateLeft(d * (2 * d + 1), 5);
            int t = rotateLeft(b * (2 * b + 1), 5);
            c = rotateRight(c - s[2 * r + 1], t) ^ u;
            a = rotateRight(a - s[2 * r], u) ^ t;
        }

        d -= s[1];
        b -= s[0];

        return wordsToBytes(new int[]{a, b, c, d});
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
        ByteBuffer.wrap(bytes).asIntBuffer().get(words);
        return words;
    }

    private static byte[] wordsToBytes(int[] words) {
        ByteBuffer buf = ByteBuffer.allocate(words.length * 4);
        buf.asIntBuffer().put(words);
        return buf.array();
    }

    private static int rotateLeft(int value, int shift) {
        return (value << shift) | (value >>> (WORD_SIZE - shift));
    }

    private static int rotateRight(int value, int shift) {
        return (value >>> shift) | (value << (WORD_SIZE - shift));
    }

    // 测试用例---------------------------------------------------
    public static void main(String[] args) {
        byte[] key = UTF_8.encode("password");
        byte[] plaintext = UTF_8.encode("This is a test.");
        RC6 rc6 = new RC6(key);

        // 加密（自动填充到16 字节）
        byte[] ciphertext = rc6.encrypt(plaintext);
        System.out.println("加密结果（十六进制）: " + bytesToHex(ciphertext));

        // 解密（自动去填充）
        byte[] decrypted = rc6.decrypt(ciphertext);
        System.out.println("解密结果: " + bytesToHex(decrypted));
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xFF));
        }
        return sb.toString();
    }
}

