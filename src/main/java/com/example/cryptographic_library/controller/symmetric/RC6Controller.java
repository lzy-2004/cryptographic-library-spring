package com.example.cryptographic_library.controller.symmetric;

import com.example.cryptographic_library.dto.symmetric.RC6Request;
import com.example.cryptographic_library.dto.symmetric.RC6Response;
import com.example.cryptographic_library.service.symmetric.RC6Service;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

/**
 * RC6对称加密接口
 *
 * <p>提供基于RC6算法的加密服务，采用ECB模式实现（需配合填充使用）</p>
 *
 * <strong>安全提示：</strong>本实现使用ECB模式，建议配合随机IV使用CBC模式增强安全性
 */
@RestController
@RequestMapping("/api/rc6")
@CrossOrigin(origins = "http://localhost:3000")
public class RC6Controller {

    @Autowired
    private RC6Service rc6Service;

    /**
     * RC6加密接口
     * @param request 包含密钥、明文和输出编码的请求体
     * @return 加密结果响应
     * @apiNote 示例请求：{"key": "secret", "data": "plaintext", "outputEncoding": "base64"}
     */
    @PostMapping("/encrypt")
    public RC6Response process(@RequestBody RC6Request request) {
        return rc6Service.encrypt(request.getKey(), request.getData(), request.getOutputEncoding());
    }
    /**
     * RC6解密接口
     * @param request 包含密钥、密文和输入编码的请求体
     * @return 解密结果响应
     * @apiNote 示例请求：{"key": "secret", "data": "U2FsdGVkX1...", "outputEncoding": "base64"}
     */
    @PostMapping("/decrypt")
    public RC6Response decrypt(@RequestBody RC6Request request) {
        return rc6Service.decrypt(request.getKey(), request.getData(), request.getOutputEncoding());
    }
}
