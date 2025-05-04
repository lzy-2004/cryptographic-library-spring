package com.example.cryptographic_library.service.asymmetric;

import com.example.cryptographic_library.algorithm.asymmetric.ECC_160;
import com.example.cryptographic_library.dto.asymmetric.ECC160DTO;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.Base64;

/**
 * ECC160加密服务实现
 *
 * <p>功能特性：
 * <ul>
 *   <li>密钥对安全生成（基于SecureRandom）</li>
 *   <li>临时密钥派生机制（ECDH）</li>
 *   <li>组合式密文结构（临时公钥+数据）</li>
 *   <li>兼容RFC 7748规范</li>
 * </ul>
 */
@Service
public class ECC160Service {
    private final Base64.Encoder encoder = Base64.getEncoder();
    private final Base64.Decoder decoder = Base64.getDecoder();

    /**
     * 生成ECC160密钥对
     * @return 包含Base64编码公私钥的响应对象
     * @throws SecurityException 密钥生成失败时抛出
     */
    public ECC160DTO.KeyPairResponse generateKeyPair() {
        ECC_160.KeyPair keyPair = ECC_160.generateKeyPair();
        return new ECC160DTO.KeyPairResponse(
                encoder.encodeToString(keyPair.publicKey),
                encoder.encodeToString(keyPair.privateKey)
        );
    }

    /**
     * 执行加密操作
     * @param request 加密请求参数
     * @return 加密结果响应
     * @throws IllegalArgumentException 公钥格式错误或加密失败时抛出
     */
    public ECC160DTO.CryptoResponse encrypt(ECC160DTO.EncryptRequest request) {
        try {
            // 解码公钥
            byte[] publicKey = decoder.decode(request.getPublicKey());
            
            // 验证公钥长度
            if (publicKey.length != 20) {
                throw new IllegalArgumentException("公钥格式错误: 长度必须为20字节");
            }
            
            // 处理明文 - 支持普通字符串或Base64编码
            byte[] plaintext;
            if (request.isBase64()) {
                // 如果明文已经是Base64编码，则解码
                try {
                    plaintext = decoder.decode(request.getPlaintext());
                } catch (IllegalArgumentException e) {
                    throw new IllegalArgumentException("明文Base64格式错误: " + e.getMessage());
                }
            } else {
                // 直接使用字符串的UTF-8编码
                plaintext = request.getPlaintext().getBytes("UTF-8");
            }
            
            // 执行加密
            ECC_160.Ciphertext ciphertext = ECC_160.encrypt(publicKey, plaintext);

            // 组合临时公钥和密文
            byte[] combined = new byte[ciphertext.ephemeralPubKey.length + ciphertext.encryptedData.length];
            System.arraycopy(ciphertext.ephemeralPubKey, 0, combined, 0, ciphertext.ephemeralPubKey.length);
            System.arraycopy(ciphertext.encryptedData, 0, combined, ciphertext.ephemeralPubKey.length, ciphertext.encryptedData.length);

            // 加密结果始终是Base64编码
            return new ECC160DTO.CryptoResponse(encoder.encodeToString(combined), true);
        } catch (IllegalArgumentException e) {
            // 特定业务异常直接抛出
            throw e;
        } catch (Exception e) {
            // 包装其他异常
            throw new IllegalArgumentException("加密失败: " + e.getMessage(), e);
        }
    }

    /**
     * 执行解密操作
     * @param request 解密请求参数
     * @return 解密结果响应，包含原始明文字符串
     * @throws IllegalArgumentException 密文格式错误或解密失败时抛出
     */
    public ECC160DTO.CryptoResponse decrypt(ECC160DTO.DecryptRequest request) {
        try {
            byte[] privateKey = decoder.decode(request.getPrivateKey());
            byte[] ciphertext = decoder.decode(request.getCiphertext());
            
            // 检查密文长度是否合理 (至少需要临时公钥20字节 + 1字节数据)
            if (ciphertext.length < 21) {
                throw new IllegalArgumentException("密文格式错误: 长度不足，无法提取临时公钥");
            }
            
            // 提取临时公钥和加密数据
            byte[] ephemeralPubKey = Arrays.copyOfRange(ciphertext, 0, 20);
            byte[] encryptedData = Arrays.copyOfRange(ciphertext, 20, ciphertext.length);
            
            // 执行解密
            byte[] decrypted = ECC_160.decrypt(privateKey, new ECC_160.Ciphertext(ephemeralPubKey, encryptedData));
            
            // 将解密结果转换为字符串（假设原始明文是UTF-8编码的字符串）
            String decryptedStr = new String(decrypted, "UTF-8");
            
            // 返回原始字符串，而不是Base64编码
            return new ECC160DTO.CryptoResponse(decryptedStr, false);
        } catch (IllegalArgumentException e) {
            // 特定业务异常直接抛出
            throw e;
        } catch (Exception e) {
            // 包装其他异常
            throw new IllegalArgumentException("解密失败: " + e.getMessage(), e);
        }
    }
}

