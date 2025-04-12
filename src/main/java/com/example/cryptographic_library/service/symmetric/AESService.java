package com.example.cryptographic_library.service.symmetric;

import com.example.cryptographic_library.algorithm.encode.Base64;
import com.example.cryptographic_library.algorithm.encode.UTF_8;
import com.example.cryptographic_library.algorithm.symmetric.AES;
import com.example.cryptographic_library.dto.symmetric.AESResponse;
import org.springframework.stereotype.Service;

/**
 * AES对称加密服务实现
 *
 * <p>功能特性：
 * <ul>
 *   <li>支持128/192/256位密钥长度</li>
 *   <li>PKCS7填充方案</li>
 *   <li>支持Hex/Base64编码输出</li>
 *   <li>自动密钥校验与转换</li>
 * </ul>
 */
@Service
public class AESService {
    /**
     * 执行加密操作
     * @param key 加密密钥（UTF-8 字符串，长度16/24/32 字节）
     * @param plaintext 明文数据（UTF-8 编码）
     * @param encoding 输出编码格式（hex/base64）
     * @return 加密结果响应
     * @throws IllegalArgumentException 密钥长度不符合要求时抛出
     */
    public AESResponse encrypt(String key, String plaintext, String encoding) {
        try {
            AES aes = new AES(UTF_8.encode(key));
            byte[] encrypted = aes.encrypt(UTF_8.encode(plaintext));

            return new AESResponse(0, "加密成功", encodeResult(encrypted, encoding));
        } catch (Exception e) {
            return new AESResponse(-1, "加密失败: " + e.getMessage(), null);
        }
    }

    /**
     * 执行解密操作
     * @param key 解密密钥（需与加密密钥一致）
     * @param ciphertext 密文字符串（需与加密输出格式匹配）
     * @param encoding 输入编码格式（hex/base64）
     * @return 解密结果响应
     * @throws IllegalArgumentException 输入数据格式错误时抛出
     */
    public AESResponse decrypt(String key, String ciphertext, String encoding) {
        try {
            AES aes = new AES(UTF_8.encode(key));
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
