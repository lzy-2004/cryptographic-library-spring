package com.example.cryptographic_library.service.hash;

import com.example.cryptographic_library.algorithm.encode.Base64;
import com.example.cryptographic_library.algorithm.encode.UTF_8;
import com.example.cryptographic_library.algorithm.hash.PBKDF2;
import com.example.cryptographic_library.dto.hash.PBKDF2Response;
import org.springframework.stereotype.Service;

@Service
public class PBKDF2Service {

    public PBKDF2Response deriveKey(String password,
                                    String salt,
                                    int iterations,
                                    int keyLength,
                                    String outputEncoding) {
        try {
            validateParameters(password, salt, iterations, keyLength);
            byte[] saltBytes = UTF_8.encode(salt); // 直接编码原始字符串

            byte[] key = PBKDF2.deriveKey(
                    password.toCharArray(),
                    saltBytes,
                    iterations,
                    keyLength
            );

            return new PBKDF2Response(0, "密钥派生成功",
                    encodeResult(key, outputEncoding));
        } catch (IllegalArgumentException e) {
            return new PBKDF2Response(-1, e.getMessage(), null);
        } catch (Exception e) {
            return new PBKDF2Response(-2, "服务器处理错误: " + e.getMessage(), null);
        }
    }

    private void validateParameters(String password, String salt,
                                    int iterations, int keyLength) {
        if (password == null) {
            throw new IllegalArgumentException("密码不能为空");
        }
        if (salt == null) {
            throw new IllegalArgumentException("盐值不能为空");
        }
        if (keyLength < 16 || keyLength > 1024) {
            throw new IllegalArgumentException("密钥长度需在16-1024字节之间");
        }
    }

    private String encodeResult(byte[] data, String encoding) {
        if ("base64".equalsIgnoreCase(encoding)) {
            return Base64.encode(data);
        } else if ("hex".equalsIgnoreCase(encoding)) {
            return bytesToHex(data);
        }
        throw new IllegalArgumentException("不支持的输出编码格式");
    }

    // 优化后的HEX编码方法
    private static final char[] HEX_ARRAY = "0123456789abcdef".toCharArray();
    private String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            int v = bytes[i] & 0xFF;
            hexChars[i * 2] = HEX_ARRAY[v >>> 4];
            hexChars[i * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }
}