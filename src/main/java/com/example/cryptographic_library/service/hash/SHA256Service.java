package com.example.cryptographic_library.service.hash;

import com.example.cryptographic_library.algorithm.encode.Base64;
import com.example.cryptographic_library.algorithm.hash.SHA256;
import com.example.cryptographic_library.dto.hash.SHA256Response;
import org.springframework.stereotype.Service;

@Service
public class SHA256Service {

    public SHA256Response hash(String data, String encoding) {
        try {
            validateEncoding(encoding);
            byte[] hashBytes = SHA256.hash(data.getBytes());
            return new SHA256Response(0, "哈希计算成功", encodeResult(hashBytes, encoding));
        } catch (IllegalArgumentException e) {
            return new SHA256Response(-1, e.getMessage(), null);
        } catch (Exception e) {
            return new SHA256Response(-2, "服务器内部错误", null);
        }
    }

    private void validateEncoding(String encoding) {
        if (!"hex".equalsIgnoreCase(encoding) && !"base64".equalsIgnoreCase(encoding)) {
            throw new IllegalArgumentException("不支持的编码格式: " + encoding);
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
