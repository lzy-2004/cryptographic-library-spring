package com.example.cryptographic_library.controller.asymmetric;

import com.example.cryptographic_library.dto.asymmetric.RSA1024KeyPair;
import com.example.cryptographic_library.dto.asymmetric.RSA1024Request;
import com.example.cryptographic_library.dto.asymmetric.RSA1024Response;
import com.example.cryptographic_library.service.asymmetric.RSA1024Service;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/rsa1024")
@CrossOrigin(origins = "http://localhost:3000")
public class RSA1024Controller {
    @Autowired
    private RSA1024Service service;
    /**
     * 生成RSA-1024密钥对
     * @return 包含Base64编码密钥的响应实体：
     *         - publicKey: 公钥（指数e）
     *         - privateKey: 私钥（指数d）
     *         - modulus: 模数n
     * @apiNote 密钥对使用PKCS#1标准生成，模数为1024位，适用于加密/解密操作
     */
    @GetMapping("/keypair")
    public RSA1024KeyPair generateKeyPair(){
        return service.generateKeyPair();
    }
    /**
     * 使用RSA公钥加密数据
     * @param request 加密请求体，包含：
     *                - key: Base64编码的公钥（指数e）
     *                - modulus: Base64编码的模数n
     *                - data: 待加密原始数据（明文）
     *                - encoding: 结果编码方式（base64/hex）
     * @return 加密响应实体，包含：
     *         - status: 操作状态码（0成功，-1失败）
     *         - message: 操作结果描述
     *         - result: 加密结果（根据encoding参数编码）
     * @apiNote 数据加密使用PKCS#1 v1.5填充方案，明文长度限制为117字节
     */
    @PostMapping("/encrypt")
    public RSA1024Response encrypt(@RequestBody RSA1024Request request){
        return service.encrypt(request);
    }

    /**
     * 使用RSA私钥解密数据
     * @param request 解密请求体，包含：
     *                - key: Base64编码的私钥（指数d）
     *                - modulus: Base64编码的模数n
     *                - data: 待解密数据（密文）
     *                - encoding: 输入数据编码方式（base64/hex）
     * @return 解密响应实体，包含：
     *         - status: 操作状态码（0成功，-1失败）
     *         - message: 操作结果描述
     *         - result: 解密后的原始明文
     * @apiNote 要求密文必须通过本系统加密生成，支持128字节标准密文长度
     */
    @PostMapping("/decrypt")
    public RSA1024Response decrypt(@RequestBody RSA1024Request request){
        return service.decrypt(request);
    }
}
