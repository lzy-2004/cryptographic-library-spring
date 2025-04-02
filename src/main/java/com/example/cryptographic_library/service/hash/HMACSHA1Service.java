package com.example.cryptographic_library.service.hash;

import com.example.cryptographic_library.algorithm.encode.Base64;
import com.example.cryptographic_library.algorithm.encode.UTF_8;
import com.example.cryptographic_library.algorithm.hash.HMacSHA1;
import com.example.cryptographic_library.dto.hash.HMACSHA1Response;
import org.springframework.stereotype.Service;

/**
 * HMAC-SHA1签名服务实现
 *
 * <p>支持以下编码格式输出：
 * <ul>
 *   <li>hex: 十六进制字符串（默认）</li>
 *   <li>base64: Base64编码字符串</li>
 * </ul>
 */
@Service
public class HMACSHA1Service {
    /**
     * 生成HMAC-SHA1签名
     * @param key 签名密钥（UTF-8 编码）
     * @param data 待签名数据
     * @param encoding 输出格式（hex/base64）
     * @return 签名结果响应
     * @see HMacSHA1#calculate(byte[])
     */
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
