package com.example.cryptographic_library.controller.symmetric;

import com.example.cryptographic_library.dto.symmetric.SM4Request;
import com.example.cryptographic_library.dto.symmetric.SM4Response;
import com.example.cryptographic_library.service.symmetric.SM4Service;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

/**
 * SM4国密算法加密接口
 *
 * <p>提供符合GB/T 32907-2016标准的128位分组密码服务</p>
 *
 * <strong>安全提示：</strong>当前实现采用ECB模式，建议配合GMAC等认证模式使用增强安全性
 */
@RestController
@RequestMapping("/api/sm4")
@CrossOrigin(origins = "http://localhost:3000")
public class SM4Controller {

    @Autowired
    private SM4Service sm4Service;

    /**
     * SM4加密接口
     * @param request 包含密钥、明文和输出编码的请求体
     * @return 加密结果响应
     * @apiNote 示例请求：{"key": "1234567890abcdef", "data": "明文数据", "encoding": "base64"}
     */
    @PostMapping("/encrypt")
    public SM4Response encrypt(@RequestBody SM4Request request) {
        return sm4Service.encrypt(request.getKey(), request.getData(), request.getEncoding());
    }

    /**
     * SM4解密接口
     * @param request 包含密钥、密文和输入编码的请求体
     * @return 解密结果响应
     * @apiNote 示例请求：{"key": "1234567890abcdef", "data": "U2FsdGVkX1...", "encoding": "base64"}
     */
    @PostMapping("/decrypt")
    public SM4Response decrypt(@RequestBody SM4Request request) {
        return sm4Service.decrypt(request.getKey(), request.getData(), request.getEncoding());
    }
}