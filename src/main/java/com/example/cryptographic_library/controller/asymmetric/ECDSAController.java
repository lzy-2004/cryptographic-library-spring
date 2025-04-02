package com.example.cryptographic_library.controller.asymmetric;

import com.example.cryptographic_library.dto.asymmetric.ECDSADTO;
import com.example.cryptographic_library.service.asymmetric.ECDSAService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * ECDSA椭圆曲线签名接口
 *
 * <p>基于SECP160R1曲线实现，提供数字签名生成与验证功能，符合FIPS 186-4标准</p>
 *
 * <strong>安全提示：</strong>私钥需严格保密，签名过程需使用安全随机数生成k值
 */
@RestController
@RequestMapping("/api/ecdsa")
@CrossOrigin(origins = "http://localhost:3000")
public class ECDSAController {

    private final ECDSAService ecdsaService;

    public ECDSAController(ECDSAService ecdsaService) {
        this.ecdsaService = ecdsaService;
    }

    /**
     * 生成ECDSA椭圆曲线密钥对
     * @return 响应实体包含：
     *         - publicKeyX: Base64编码的公钥X坐标
     *         - publicKeyY: Base64编码的公钥Y坐标
     *         - privateKey: Base64编码的私钥
     * @apiNote 生成的密钥对适用于ECDSA算法签名/验证操作，基于SECP160R1曲线
     */
    @GetMapping("/keypair")
    public ResponseEntity<ECDSADTO.KeyPairResponse> generateKeyPair() {
        return ResponseEntity.ok(ecdsaService.generateKeyPair());
    }

    /**
     * 使用ECDSA算法进行数据签名
     * @param request 签名请求体，包含：
     *                - privateKey: Base64编码的签名方私钥
     *                - message: 原始待签名消息（未编码）
     * @return 签名响应实体，包含：
     *         - r: Base64编码的签名R分量
     *         - s: Base64编码的签名S分量
     * @apiNote 消息以原始字节形式处理，签名结果使用DER编码格式的(R,S)组合
     */
    @PostMapping("/sign")
    public ResponseEntity<ECDSADTO.SignResponse> sign(
            @RequestBody ECDSADTO.SignRequest request) {
        return ResponseEntity.ok(ecdsaService.sign(request));
    }

    /**
     * 验证ECDSA签名有效性
     * @param request 验证请求体，包含：
     *                - publicKeyX: Base64编码的签名方公钥X坐标
     *                - publicKeyY: Base64编码的签名方公钥Y坐标
     *                - message: 原始待验证消息（未编码）
     *                - signatureR: Base64编码的签名R分量
     *                - signatureS: Base64编码的签名S分量
     * @return 验证响应实体，包含：
     *         - valid: 验证结果布尔值
     *         - message: 验证结果描述信息
     * @apiNote 公钥需与签名时使用的私钥对应，消息需与签名原始消息完全一致
     */
    @PostMapping("/verify")
    public ResponseEntity<ECDSADTO.VerifyResponse> verify(
            @RequestBody ECDSADTO.VerifyRequest request) {
        return ResponseEntity.ok(ecdsaService.verify(request));
    }
}
