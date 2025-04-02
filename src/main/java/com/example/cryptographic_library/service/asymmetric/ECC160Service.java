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
     * @throws IllegalArgumentException 公钥格式错误时抛出
     */
    public ECC160DTO.CryptoResponse encrypt(ECC160DTO.EncryptRequest request) {
        byte[] publicKey = decoder.decode(request.getPublicKey());
        byte[] plaintext = decoder.decode(request.getPlaintext());
        ECC_160.Ciphertext ciphertext = ECC_160.encrypt(publicKey, plaintext);

        // 组合临时公钥和密文
        byte[] combined = new byte[ciphertext.ephemeralPubKey.length + ciphertext.encryptedData.length];
        System.arraycopy(ciphertext.ephemeralPubKey, 0, combined, 0, ciphertext.ephemeralPubKey.length);
        System.arraycopy(ciphertext.encryptedData, 0, combined, ciphertext.ephemeralPubKey.length, ciphertext.encryptedData.length);

        return new ECC160DTO.CryptoResponse(encoder.encodeToString(combined));
    }

    /**
     * 执行解密操作
     * @param request 解密请求参数
     * @return 解密结果响应
     */
    public ECC160DTO.CryptoResponse decrypt(ECC160DTO.DecryptRequest request) {
        byte[] privateKey = decoder.decode(request.getPrivateKey());
        byte[] ciphertext = decoder.decode(request.getCiphertext());
        byte[] decrypted = ECC_160.decrypt(privateKey, new ECC_160.Ciphertext(
                Arrays.copyOfRange(ciphertext, 0, 20), // 前20字节是临时公钥
                Arrays.copyOfRange(ciphertext, 20, ciphertext.length) // 剩余是密文
        ));
        return new ECC160DTO.CryptoResponse(encoder.encodeToString(decrypted));
    }
}

