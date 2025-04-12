package com.example.cryptographic_library.algorithm.encode;

public class Base64 {
    private static final String BASE64_CHARS =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    private static final int MASK_6BIT = 0x3F;

    public static String encode(byte[] data) {
        StringBuilder result = new StringBuilder();
        int paddingCount = (3 - (data.length % 3)) % 3;
        int[] buffer = new int[3];
        for (int i = 0; i < data.length; i += 3) {
            // 将3个字节装入buffer
            buffer[0] = data[i] & 0xFF;
            buffer[1] = (i+1 < data.length) ? data[i+1] & 0xFF : 0;
            buffer[2] = (i+2 < data.length) ? data[i+2] & 0xFF : 0;
            // 转换为4个Base64字符
            int b64Index1 = buffer[0] >>> 2;
            int b64Index2 = ((buffer[0] & 0x03) << 4) | (buffer[1] >>> 4);
            int b64Index3 = ((buffer[1] & 0x0F) << 2) | (buffer[2] >>> 6);
            int b64Index4 = buffer[2] & MASK_6BIT;

            result.append(BASE64_CHARS.charAt(b64Index1));
            result.append(BASE64_CHARS.charAt(b64Index2));
            result.append((i+1 < data.length) ? BASE64_CHARS.charAt(b64Index3) : "=");
            result.append((i+2 < data.length) ? BASE64_CHARS.charAt(b64Index4) : "=");
        }
        return result.toString();
    }

    public static byte[] decode(String encoded) {
        if (encoded.length() % 4 != 0) {
            throw new IllegalArgumentException("Invalid Base64 string length");
        }
        int paddingCount = 0;
        if (encoded.endsWith("==")) {
            paddingCount = 2;
        } else if (encoded.endsWith("=")) {
            paddingCount = 1;
        }
        byte[] result = new byte[((encoded.length() * 3) / 4) - paddingCount];
        int[] buffer = new int[4];
        int resultIndex = 0;
        for (int i = 0; i < encoded.length(); i += 4) {
            // 填充处理
            for (int j = 0; j < 4; j++) {
                char c = encoded.charAt(i + j);
                if (c == '=') {
                    buffer[j] = 0;
                } else {
                    int index = BASE64_CHARS.indexOf(c);
                    if (index == -1) {
                        throw new IllegalArgumentException("Invalid character: " + c);
                    }
                    buffer[j] = index;
                }
            }
            // 转换为3个字节
            result[resultIndex++] = (byte) ((buffer[0] << 2) | (buffer[1] >>> 4));
            if (resultIndex < result.length) {
                result[resultIndex++] = (byte) ((buffer[1] << 4) | (buffer[2] >>> 2));
            }
            if (resultIndex < result.length) {
                result[resultIndex++] = (byte) ((buffer[2] << 6) | buffer[3]);
            }
        }
        return result;
    }

    // 测试用例
    public static void main(String[] args) {
        // RFC 4648测试向量
        testEncodeDecode("", "");
        testEncodeDecode("f", "Zg==");
        testEncodeDecode("fo", "Zm8=");
        testEncodeDecode("你好", "5L2g5aW9");
        testEncodeDecode("Hello World!", "SGVsbG8gV29ybGQh");
    }

    private static void testEncodeDecode(String original, String expectedEncoded) {
        try {
            byte[] data = original.getBytes(); // 明确编码
            String encoded = Base64.encode(data);
            byte[] decoded = Base64.decode(encoded);
            String decodedStr = new String(decoded); // 明确解码

            System.out.println("原始: " + original);
            System.out.println("编码: " + encoded);
            System.out.println("解码: " + decodedStr);
            System.out.println("测试结果: " +
                    ((encoded.equals(expectedEncoded) && original.equals(decodedStr))
                            ? "通过" : "失败"));
        } catch (Exception e) {
            System.out.println("测试异常: " + e.getMessage());
        }
        System.out.println("-------------------");
    }

}
