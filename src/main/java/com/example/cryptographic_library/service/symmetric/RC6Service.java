package com.example.cryptographic_library.service.symmetric;

import com.example.cryptographic_library.algorithm.encode.Base64;
import com.example.cryptographic_library.algorithm.encode.UTF_8;
import com.example.cryptographic_library.algorithm.symmetric.RC6;

import com.example.cryptographic_library.dto.symmetric.RC6Response;

import org.springframework.stereotype.Service;

@Service
public class RC6Service {

    public RC6Response encrypt(String key, String plaintext, String encoding) {
        try {
            validateKeyLength(UTF_8.encode(key));
            RC6 rc6 = new RC6(UTF_8.encode(key)); // 修改点1
            byte[] encrypted = rc6.encrypt(UTF_8.encode(plaintext)); // 修改点2

            return new RC6Response(0, "加密成功", encodeResult(encrypted, encoding));
        } catch (Exception e) {
            return new RC6Response(-1, "加密失败: " + e.getMessage(), null);
        }
    }

    public RC6Response decrypt(String key, String ciphertext, String encoding) {
        try {
            validateKeyLength(UTF_8.encode(key));
            RC6 rc6 = new RC6(UTF_8.encode(key)); // 修改点3
            byte[] data = decodeInput(ciphertext, encoding);
            byte[] decrypted = rc6.decrypt(data);

            return new RC6Response(0, "解密成功", UTF_8.decode(decrypted)); // 修改点4
        } catch (Exception e) {
            return new RC6Response(-1, "解密失败: " + e.getMessage(), null);
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

    private void validateKeyLength(byte[] key) {
        if (key.length < 4 || key.length > 32) {
            throw new IllegalArgumentException("密钥长度需在4-32字节之间");
        }
    }
}
