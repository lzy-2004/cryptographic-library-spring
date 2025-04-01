package com.example.cryptographic_library.service.hash;

import com.example.cryptographic_library.algorithm.encode.Base64;
import com.example.cryptographic_library.algorithm.encode.UTF_8;
import com.example.cryptographic_library.algorithm.hash.HMacSHA1;
import com.example.cryptographic_library.dto.hash.HMACSHA1Response;
import org.springframework.stereotype.Service;

@Service
public class HMACSHA1Service {
    public HMACSHA1Response hash(String key, String data, String encoding) {
        try {
            HMacSHA1 hmacsha1 = new HMacSHA1(UTF_8.encode(key));
            byte[] hashBytes = hmacsha1.calculate(UTF_8.encode(data));
            String result = encodeResult(hashBytes, encoding);
            return new HMACSHA1Response(0, "哈希计算成功", result);
        } catch (Exception e) {
            return new HMACSHA1Response(-1, "哈希失败: " + e.getMessage(), null);
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
