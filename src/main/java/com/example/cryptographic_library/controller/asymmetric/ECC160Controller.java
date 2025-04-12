package com.example.cryptographic_library.controller.asymmetric;

import com.example.cryptographic_library.dto.asymmetric.ECC160DTO;
import com.example.cryptographic_library.service.asymmetric.ECC160Service;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * ECC160椭圆曲线加密接口
 *
 * <p>基于secp160r1曲线实现，提供密钥生成、加密解密功能，符合SECG标准</p>
 *
 * <strong>安全提示：</strong>本实现使用临时密钥派生机制，建议定期更换密钥对提升安全性
 */
@RestController
@RequestMapping("/api/ecc160")
@CrossOrigin(origins = "http://localhost:3000")
public class ECC160Controller {
    private final ECC160Service cryptoService;

    public ECC160Controller(ECC160Service cryptoService) {
        this.cryptoService = cryptoService;
    }

    /**
     * 生成ECC160密钥对
     * @return 包含Base64编码公私钥的响应实体
     * @apiNote 私钥需安全存储，公钥可公开分发
     */
    @GetMapping("/keypair")
    public ResponseEntity<ECC160DTO.KeyPairResponse> generateKeyPair() {
        return ResponseEntity.ok(cryptoService.generateKeyPair());
    }

    /**
     * 使用ECC160算法加密数据
     * @param request 加密请求体，包含：
     *                - publicKey: Base64编码的接收方公钥
     *                - plaintext: Base64编码的待加密原始数据
     * @return 加密响应实体，data字段包含Base64编码的加密结果（临时公钥+密文组合）
     * @apiNote 加密结果格式：前20 字节为临时公钥，剩余部分为加密数据
     */
    @PostMapping("/encrypt")
    public ResponseEntity<ECC160DTO.CryptoResponse> encrypt(
            @RequestBody ECC160DTO.EncryptRequest request) {
        return ResponseEntity.ok(cryptoService.encrypt(request));
    }

    /**
     * 使用ECC160算法解密数据
     * @param request 解密请求体，包含：
     *                - privateKey: Base64编码的接收方私钥
     *                - ciphertext: Base64编码的加密数据（需包含临时公钥）
     * @return 解密响应实体，data字段包含Base64编码的原始明文
     * @apiNote 密文格式要求：必须是由本系统加密生成的组合格式数据
     */
    @PostMapping("/decrypt")
    public ResponseEntity<ECC160DTO.CryptoResponse> decrypt(
            @RequestBody ECC160DTO.DecryptRequest request) {
        return ResponseEntity.ok(cryptoService.decrypt(request));
    }
}
