package com.example.cryptographic_library.algorithm.encode;

/**
 * 十六进制编解码工具类
 */
public class Hex {

    // 十六进制字符表
    private static final char[] HEX_DIGITS = "0123456789abcdef".toCharArray();

    /**
     * 将字节数组编码为十六进制字符串
     *
     * @param data 字节数组
     * @return 十六进制字符串
     */
    public static String encode(byte[] data) {
        StringBuilder sb = new StringBuilder(data.length * 2);
        for (byte b : data) {
            sb.append(HEX_DIGITS[(b >> 4) & 0x0f]);
            sb.append(HEX_DIGITS[b & 0x0f]);
        }
        return sb.toString();
    }

    /**
     * 将十六进制字符串解码为字节数组
     *
     * @param hexString 十六进制字符串
     * @return 字节数组
     * @throws IllegalArgumentException 如果输入包含非法十六进制字符或长度不是偶数
     */
    public static byte[] decode(String hexString) {
        if (hexString == null || hexString.length() % 2 != 0) {
            throw new IllegalArgumentException("Hex string must have even length");
        }

        int len = hexString.length();
        byte[] data = new byte[len / 2];

        for (int i = 0; i < len; i += 2) {
            int hi = Character.digit(hexString.charAt(i), 16);
            int lo = Character.digit(hexString.charAt(i + 1), 16);
            if (hi < 0 || lo < 0) {
                throw new IllegalArgumentException("Invalid hex character: " + hexString.substring(i, i + 2));
            }
            data[i / 2] = (byte) ((hi << 4) | lo);
        }

        return data;
    }

    /**
     * 主方法用于测试
     */
    public static void main(String[] args) {
        String input = "李孜炎";
        byte[] bytes = UTF_8.encode(input);
        String hex = encode(bytes);
        byte[] decodedBytes = decode(hex);
        String decodedStr = UTF_8.decode(decodedBytes);

        System.out.println("原始输入: " + input);
        System.out.println("Hex编码: " + hex);
        System.out.println("解码后: " + decodedStr);
    }
}
