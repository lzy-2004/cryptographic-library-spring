package com.example.cryptographic_library.controller.hash;

import com.example.cryptographic_library.dto.hash.HMACSHA256Request;
import com.example.cryptographic_library.dto.hash.HMACSHA256Response;
import com.example.cryptographic_library.service.hash.HMACSHA256Service;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

/**
 * HMAC-SHA256认证接口
 *
 * <p>提供基于RFC 2104标准的HMAC-SHA256签名生成服务</p>
 */
@RestController
@RequestMapping("/api/hmacsha256")
@CrossOrigin(origins = "http://localhost:3000")
public class HMACSHA256Controller {
    @Autowired
    private HMACSHA256Service hmacsha256Service;

    /**
     * HMAC-SHA256签名生成接口
     * @param request 包含密钥、数据和编码格式的请求体
     * @return 签名结果响应对象（32 字节的哈希值）
     * @apiNote 示例请求：{"key": "secret", "data": "message", "encoding": "base64"}
     */
    @PostMapping("/hash")
    public HMACSHA256Response hash(@RequestBody HMACSHA256Request request) {
        return hmacsha256Service.hash(request.getKey(),request.getData(), request.getEncoding());
    }
}
