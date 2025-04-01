package com.example.cryptographic_library.service.hash;

import com.example.cryptographic_library.algorithm.encode.Base64;
import com.example.cryptographic_library.algorithm.encode.UTF_8;
import com.example.cryptographic_library.algorithm.hash.HMacSHA256;
import com.example.cryptographic_library.dto.hash.HMACSHA256Response;
import org.springframework.stereotype.Service;

@Service
public class HMACSHA256Service {
    public HMACSHA256Response hash(String key, String data, String encoding) {
        try {
            HMacSHA256 hmacsha256 = new HMacSHA256(UTF_8.encode(key));
            byte[] hashBytes = hmacsha256.compute(UTF_8.encode(data));
            String result = encodeResult(hashBytes, encoding);
            return new HMACSHA256Response(0, "哈希计算成功", result);
        } catch (Exception e) {
            return new HMACSHA256Response(-1, "哈希失败: " + e.getMessage(), null);
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
