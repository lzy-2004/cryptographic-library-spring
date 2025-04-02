package com.example.cryptographic_library.controller.symmetric;

import com.example.cryptographic_library.dto.symmetric.AESRequest;
import com.example.cryptographic_library.dto.symmetric.AESResponse;
import com.example.cryptographic_library.service.symmetric.AESService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

/**
 * AES对称加密接口
 *
 * <p>提供符合FIPS 197标准的AES加密服务，当前实现采用ECB模式（需配合填充使用）</p>
 *
 * <strong>安全提示：</strong>ECB模式不适用于加密重复模式数据，生产环境建议使用CBC/GCM模式
 */
@RestController
@RequestMapping("/api/aes")
@CrossOrigin(origins = "http://localhost:3000")
public class AESController {

    @Autowired
    private AESService aesService;

    /**
     * AES加密接口
     * @param request 包含密钥、明文和输出编码的请求体
     * @return 加密结果响应
     * @apiNote 示例请求：{"key": "secretkey12345678", "data": "plaintext", "outputEncoding": "base64"}
     */
    @PostMapping("/encrypt")
    public AESResponse encrypt(@RequestBody AESRequest request) {
        return aesService.encrypt(request.getKey(), request.getData(), request.getOutputEncoding());
    }
    /**
     * AES解密接口
     * @param request 包含密钥、密文和输入编码的请求体
     * @return 解密结果响应
     * @apiNote 示例请求：{"key": "secretkey12345678", "data": "U2FsdGVkX1...", "outputEncoding": "base64"}
     */
    @PostMapping("/decrypt")
    public AESResponse decrypt(@RequestBody AESRequest request) {
        return aesService.decrypt(request.getKey(), request.getData(), request.getOutputEncoding());
    }
}