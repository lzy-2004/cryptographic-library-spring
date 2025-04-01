package com.example.cryptographic_library.service.symmetric;

import com.example.cryptographic_library.algorithm.encode.Base64;
import com.example.cryptographic_library.algorithm.encode.UTF_8;
import com.example.cryptographic_library.algorithm.symmetric.AES;
import com.example.cryptographic_library.dto.symmetric.AESResponse;
import org.springframework.stereotype.Service;

@Service
public class AESService {
    public AESResponse encrypt(String key, String plaintext, String encoding) {
        try {
            AES aes = new AES(UTF_8.encode(key)); // 修改点1
            byte[] encrypted = aes.encrypt(UTF_8.encode(plaintext)); // 修改点2

            return new AESResponse(0, "加密成功", encodeResult(encrypted, encoding));
        } catch (Exception e) {
            return new AESResponse(-1, "加密失败: " + e.getMessage(), null);
        }
    }

    public AESResponse decrypt(String key, String ciphertext, String encoding) {
        try {
            AES aes = new AES(UTF_8.encode(key)); // 修改点3
            byte[] data = decodeInput(ciphertext, encoding);
            byte[] decrypted = aes.decrypt(data);

            return new AESResponse(0, "解密成功", UTF_8.decode(decrypted));
        } catch (Exception e) {
            return new AESResponse(-1, "解密失败: " + e.getMessage(), null);
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
