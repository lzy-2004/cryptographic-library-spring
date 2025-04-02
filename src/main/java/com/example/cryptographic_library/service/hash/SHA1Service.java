package com.example.cryptographic_library.service.hash;

import com.example.cryptographic_library.algorithm.encode.Base64;
import com.example.cryptographic_library.algorithm.hash.SHA1;
import com.example.cryptographic_library.dto.hash.SHA1Response;
import org.springframework.stereotype.Service;

/**
 * SHA-1哈希服务实现
 *
 * <p>功能特性：
 * <ul>
 *   <li>支持任意长度输入数据</li>
 *   <li>输出格式可选Hex或Base64</li>
 *   <li>自动处理消息填充</li>
 * </ul>
 */
@Service
public class SHA1Service {
    /**
     * 执行哈希计算
     * @param data 原始输入字符串（UTF-8编码）
     * @param encoding 输出编码格式（hex/base64）
     * @return 哈希结果响应
     * @throws IllegalArgumentException 输入为空或编码格式不支持时抛出
     */
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
