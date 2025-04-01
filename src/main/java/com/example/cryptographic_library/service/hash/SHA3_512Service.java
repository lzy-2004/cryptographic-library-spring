package com.example.cryptographic_library.service.hash;

import com.example.cryptographic_library.algorithm.encode.Base64;
import com.example.cryptographic_library.algorithm.hash.SHA3_512;
import com.example.cryptographic_library.dto.hash.SHA3_512Response;
import org.springframework.stereotype.Service;

@Service
public class SHA3_512Service {

    public SHA3_512Response hash(String data, String encoding) {
        try {
            validateInput(data, encoding);
            byte[] hashBytes = SHA3_512.hash(data.getBytes());
            return new SHA3_512Response(0, "哈希计算成功", encodeResult(hashBytes, encoding));
        } catch (IllegalArgumentException e) {
            return new SHA3_512Response(-1, e.getMessage(), null);
        } catch (Exception e) {
            return new SHA3_512Response(-2, "服务器内部错误", null);
        }
    }

    private void validateInput(String data, String encoding) {
        if (data == null ) {
            throw new IllegalArgumentException("输入数据不能为空");
        }
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
