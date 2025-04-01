package com.example.cryptographic_library.algorithm.encode;

public class UTF_8 {
    // UTF-8编码掩码
    private static final int ONE_BYTE_MASK = 0b10000000;
    private static final int TWO_BYTE_MASK = 0b11100000;
    private static final int THREE_BYTE_MASK = 0b11110000;
    private static final int FOUR_BYTE_MASK = 0b11111000;

    // 编码范围校验
    private static final int MIN_CODE_POINT = 0x0000;
    private static final int MAX_CODE_POINT = 0x10FFFF;

    // 编码方法
    public static byte[] encode(String input) {
        ByteBuffer buffer = new ByteBuffer(input.length() * 4);
        for (int i = 0; i < input.length(); i++) {
            int codePoint = input.codePointAt(i);
            validateCodePoint(codePoint);

            if (codePoint < 0x80) {
                buffer.append((byte) codePoint);
            } else if (codePoint < 0x800) {
                buffer.append((byte) (0b11000000 | (codePoint >> 6)));
                buffer.append((byte) (0b10000000 | (codePoint & 0x3F)));
            } else if (codePoint < 0x10000) {
                buffer.append((byte) (0b11100000 | (codePoint >> 12)));
                buffer.append((byte) (0b10000000 | ((codePoint >> 6) & 0x3F)));
                buffer.append((byte) (0b10000000 | (codePoint & 0x3F)));
            } else {
                buffer.append((byte) (0b11110000 | (codePoint >> 18)));
                buffer.append((byte) (0b10000000 | ((codePoint >> 12) & 0x3F)));
                buffer.append((byte) (0b10000000 | ((codePoint >> 6) & 0x3F)));
                buffer.append((byte) (0b10000000 | (codePoint & 0x3F)));
            }

            if (Character.isHighSurrogate(input.charAt(i))) i++;
        }
        return buffer.toArray();
    }

    // 解码方法
    public static String decode(byte[] bytes) {
        CharBuffer buffer = new CharBuffer(bytes.length);
        int index = 0;

        while (index < bytes.length) {
            int b = bytes[index++] & 0xFF;
            int codePoint;
            int remaining;

            if ((b & ONE_BYTE_MASK) == 0) {
                codePoint = b;
                remaining = 0;
            } else if ((b & TWO_BYTE_MASK) == 0b11000000) {
                codePoint = b & 0b00011111;
                remaining = 1;
            } else if ((b & THREE_BYTE_MASK) == 0b11100000) {
                codePoint = b & 0b00001111;
                remaining = 2;
            } else if ((b & FOUR_BYTE_MASK) == 0b11110000) {
                codePoint = b & 0b00000111;
                remaining = 3;
            } else {
                throw new IllegalArgumentException("Invalid UTF-8 byte: 0x" + Integer.toHexString(b));
            }

            for (int i = 0; i < remaining; i++) {
                if (index >= bytes.length) throw new IllegalArgumentException("Truncated UTF-8 sequence");
                int nextByte = bytes[index++] & 0xFF;
                if ((nextByte & 0b11000000) != 0b10000000) {
                    throw new IllegalArgumentException("Invalid continuation byte: 0x" + Integer.toHexString(nextByte));
                }
                codePoint = (codePoint << 6) | (nextByte & 0x3F);
            }

            validateCodePoint(codePoint);
            appendCodePoint(buffer, codePoint);
        }

        return buffer.toString();
    }

    // 辅助方法
    private static void validateCodePoint(int codePoint) {
        if (codePoint < MIN_CODE_POINT || codePoint > MAX_CODE_POINT) {
            throw new IllegalArgumentException("Invalid Unicode code point: U+"
                    + Integer.toHexString(codePoint).toUpperCase());
        }
    }

    private static void appendCodePoint(CharBuffer buffer, int codePoint) {
        if (codePoint <= 0xFFFF) {
            buffer.append((char) codePoint);
        } else {
            // 处理代理对（Surrogate Pair）
            int high = 0xD800 | ((codePoint - 0x10000) >> 10);
            int low = 0xDC00 | ((codePoint - 0x10000) & 0x3FF);
            buffer.append((char) high);
            buffer.append((char) low);
        }
    }

    // 自定义缓冲区实现
    private static class ByteBuffer {
        private byte[] array;
        private int size;

        ByteBuffer(int initialCapacity) {
            array = new byte[initialCapacity];
        }

        void append(byte b) {
            if (size == array.length) {
                byte[] newArray = new byte[array.length * 2];
                System.arraycopy(array, 0, newArray, 0, size);
                array = newArray;
            }
            array[size++] = b;
        }

        byte[] toArray() {
            byte[] result = new byte[size];
            System.arraycopy(array, 0, result, 0, size);
            return result;
        }
    }

    private static class CharBuffer {
        private char[] array;
        private int size;

        CharBuffer(int initialCapacity) {
            array = new char[initialCapacity];
        }

        void append(char c) {
            if (size == array.length) {
                char[] newArray = new char[array.length * 2];
                System.arraycopy(array, 0, newArray, 0, size);
                array = newArray;
            }
            array[size++] = c;
        }

        @Override
        public String toString() {
            return new String(array, 0, size);
        }
    }

    public static void main(String[] args) {
        String input = "你好世界";
        byte[] encoded = encode(input);
        String decoded = decode(encoded);
        System.out.println("编码: " + bytesToHex(encoded));
        System.out.println("解码: " + decoded);
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xFF));
        }
        return sb.toString();
    }
}
