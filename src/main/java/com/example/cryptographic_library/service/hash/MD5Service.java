package com.example.cryptographic_library.service.hash;

import com.example.cryptographic_library.algorithm.encode.Base64;
import com.example.cryptographic_library.algorithm.encode.UTF_8;
import com.example.cryptographic_library.algorithm.hash.MD5;
import com.example.cryptographic_library.dto.hash.MD5Response;
import org.springframework.stereotype.Service;

@Service
public class MD5Service {
    public MD5Response hash(String data, String encoding) {
        try {
            MD5 md5 = new MD5();
            md5.update(UTF_8.encode(data));
            byte[] hashBytes = md5.digest();
            String result = encodeResult(hashBytes, encoding);
            return new MD5Response(0, "哈希计算成功", result);
        } catch (Exception e) {
            return new MD5Response(-1, "哈希失败: " + e.getMessage(), null);
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
