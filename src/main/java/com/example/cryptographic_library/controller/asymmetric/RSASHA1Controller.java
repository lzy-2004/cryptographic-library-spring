package com.example.cryptographic_library.controller.asymmetric;

import com.example.cryptographic_library.dto.asymmetric.*;
import com.example.cryptographic_library.service.asymmetric.RSASHA1Service;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/rsasha1")
@CrossOrigin(origins = "http://localhost:3000")
public class RSASHA1Controller {
    @Autowired
    private RSASHA1Service service;
    /**
     * 生成RSA-SHA1签名密钥对
     * @return 包含Base64编码密钥的响应实体：
     *         - publicKey: 公钥（指数e）
     *         - privateKey: 私钥（指数d）
     *         - modulus: 模数n
     * @apiNote 密钥对基于RSA-1024算法生成，使用PKCS#1 v1.5标准，专用于SHA1签名/验证操作
     */
    @GetMapping("/keypair")
    public RSA1024KeyPair generateKeyPair(){
        return service.generateKeyPair();
    }
    /**
     * 使用RSA私钥进行SHA1签名
     * @param request 签名请求体，包含：
     *                - privateKey: Base64编码的私钥
     *                - modulus: Base64编码的模数n
     *                - data: 原始待签名消息（明文）
     * @return 签名响应实体，包含：
     *         - status: 操作状态码（0成功，-1失败）
     *         - message: 操作结果描述
     *         - result: Base64编码的签名结果
     * @apiNote 签名流程：
     *          1. 对消息进行SHA1哈希
     *          2. 使用PKCS#1 v1.5添加签名填充
     *          3. 使用私钥进行RSA加密
     *          注意：私钥需严格保密
     */
    @PostMapping("/sign")
    public RSASHA1ResponseSign sign(@RequestBody RSASHA1RequestSign request){
        return service.sign(request);
    }
    /**
     * 使用RSA公钥验证SHA1签名
     * @param request 验证请求体，包含：
     *                - publicKey: Base64编码的公钥
     *                - modulus: Base64编码的模数n
     *                - data: 原始消息（明文）
     *                - signature: Base64编码的签名
     * @return 验证响应实体，包含：
     *         - status: 操作状态码（0成功，-1失败）
     *         - message: 操作结果描述
     *         - result: 验证结果布尔值
     * @apiNote 验证流程：
     *          1. 对签名进行RSA解密
     *          2. 验证PKCS#1 v1.5填充结构
     *          3. 比对消息SHA1哈希值
     *          注意：公钥需与签名私钥对应
     */
    @PostMapping("/verify")
    public RSASHA1ResponseVerify verify(@RequestBody RSASHA1RequestVerify request){
        return service.verify(request);
    }
}
