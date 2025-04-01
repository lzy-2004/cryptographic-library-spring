package com.example.cryptographic_library.service.hash;

import com.example.cryptographic_library.algorithm.encode.Base64;
import com.example.cryptographic_library.algorithm.hash.SHA1;
import com.example.cryptographic_library.dto.hash.SHA1Response;
import org.springframework.stereotype.Service;

@Service
public class SHA1Service {
    public SHA1Response hash(String data, String encoding) {
        try {
            byte[] hashBytes = SHA1.hash(data.getBytes());
            String result = encodeResult(hashBytes, encoding);
            return new SHA1Response(0, "哈希计算成功", result);
        } catch (Exception e) {
            return new SHA1Response(-1, "哈希失败: " + e.getMessage(), null);
        }
    }

    private String encodeResult(byte[] data, String encoding) {
        if ("base64".equalsIgnoreCase(encoding)) {
            return Base64.encode(data);
        }
        return bytesToHex(data);
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xFF));
        }
        return sb.toString();
    }
}
