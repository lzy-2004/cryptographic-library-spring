package com.example.cryptographic_library.service.symmetric;

import com.example.cryptographic_library.algorithm.encode.Base64;
import com.example.cryptographic_library.algorithm.encode.UTF_8;
import com.example.cryptographic_library.algorithm.symmetric.SM4;

import com.example.cryptographic_library.dto.symmetric.SM4Response;
import org.springframework.stereotype.Service;

@Service
public class SM4Service {

    public SM4Response encrypt(String key, String plaintext, String encoding) {
        try {
            validateKey(key);
            SM4 sm4 = new SM4(UTF_8.encode(key)); // 修改点1
            byte[] encrypted = sm4.encrypt(UTF_8.encode(plaintext)); // 修改点2

            return new SM4Response(0, "加密成功", encodeResult(encrypted, encoding));
        } catch (Exception e) {
            return new SM4Response(-1, "加密失败: " + e.getMessage(), null);
        }
    }

    public SM4Response decrypt(String key, String ciphertext, String encoding) {
        try {
            validateKey(key);
            SM4 sm4 = new SM4(UTF_8.encode(key)); // 修改点3
            byte[] data = decodeInput(ciphertext, encoding);
            byte[] decrypted = sm4.decrypt(data);

            return new SM4Response(0, "解密成功", UTF_8.decode(decrypted)); // 修改点4
        } catch (Exception e) {
            return new SM4Response(-1, "解密失败: " + e.getMessage(), null);
        }
    }

    private void validateKey(String key) {
        if (key.length() != 16) {
            throw new IllegalArgumentException("密钥必须为16个字符");
        }
    }

    private String encodeResult(byte[] data, String encoding) {
        if ("base64".equalsIgnoreCase(encoding)) {
            return Base64.encode(data);
        }
        return bytesToHex(data);
    }

    private byte[] decodeInput(String input, String encoding) {
        if ("base64".equalsIgnoreCase(encoding)) {
            return Base64.decode(input);
        }
        return hexToBytes(input);
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xFF));
        }
        return sb.toString();
    }

    private byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }
}
