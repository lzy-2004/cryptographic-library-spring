package com.example.cryptographic_library.service.asymmetric;

import com.example.cryptographic_library.algorithm.asymmetric.ECDSA;
import com.example.cryptographic_library.dto.asymmetric.ECDSADTO;
import org.springframework.stereotype.Service;
import java.util.Base64; // 修改导入

/**
 * ECDSA数字签名服务实现
 *
 * <p>功能特性：
 * <ul>
 *   <li>基于SECP160R1曲线参数</li>
 *   <li>符合FIPS 186-4签名规范</li>
 *   <li>SHA-256哈希算法支持</li>
 *   <li>安全随机数生成</li>
 * </ul>
 */
@Service
public class ECDSAService {

    /**
     * 生成ECDSA密钥对
     * @return Base64编码的密钥对响应对象
     * @throws SecurityException 密钥生成失败时抛出
     */
    public ECDSADTO.KeyPairResponse generateKeyPair() {
        ECDSA.KeyPair keyPair = ECDSA.generateKeyPair();
        return new ECDSADTO.KeyPairResponse(
                Base64.getEncoder().encodeToString(keyPair.publicKeyX), // 修改编码方式
                Base64.getEncoder().encodeToString(keyPair.publicKeyY),
                Base64.getEncoder().encodeToString(keyPair.privateKey)
        );
    }

    /**
     * 生成数字签名
     * @param request 签名请求参数
     * @return 签名结果（R/S分量）
     * @throws IllegalArgumentException 私钥格式错误时抛出
     */
    public ECDSADTO.SignResponse sign(ECDSADTO.SignRequest request) {
        byte[] privateKey = Base64.getDecoder().decode(request.getPrivateKey()); // 修改解码方式
        byte[] message = request.getMessage().getBytes();

        ECDSA.Signature signature = ECDSA.sign(privateKey, message);
        return new ECDSADTO.SignResponse(
                Base64.getEncoder().encodeToString(signature.r),
                Base64.getEncoder().encodeToString(signature.s)
        );
    }

    /**
     * 验证签名有效性
     * @param request 验证请求参数
     * @return 验证结果及详细信息
     */
    public ECDSADTO.VerifyResponse verify(ECDSADTO.VerifyRequest request) {
        try {
            ECDSA.KeyPair keyPair = new ECDSA.KeyPair(
                    Base64.getDecoder().decode(request.getPublicKeyX()),
                    Base64.getDecoder().decode(request.getPublicKeyY()),
                    new byte[0]
            );

            ECDSA.Signature signature = new ECDSA.Signature(
                    Base64.getDecoder().decode(request.getSignatureR()),
                    Base64.getDecoder().decode(request.getSignatureS())
            );

            boolean isValid = ECDSA.verify(keyPair,
                    request.getMessage().getBytes(),
                    signature);

            return new ECDSADTO.VerifyResponse(
                    isValid,
                    isValid ? "签名验证成功" : "签名验证失败"
            );
        } catch (Exception e) {
            return new ECDSADTO.VerifyResponse(
                    false,
                    "验证过程出错: " + e.getMessage()
            );
        }
    }
}
