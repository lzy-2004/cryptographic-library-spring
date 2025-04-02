package com.example.cryptographic_library.controller.hash;

import com.example.cryptographic_library.dto.hash.HMACSHA1Request;
import com.example.cryptographic_library.dto.hash.HMACSHA1Response;
import com.example.cryptographic_library.service.hash.HMACSHA1Service;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

/**
 * HMAC-SHA1认证接口
 *
 * <p>提供基于RFC 2104标准的HMAC-SHA1签名生成服务</p>
 */
@RestController
@RequestMapping("/api/hmacsha1")
@CrossOrigin(origins = "http://localhost:3000")
public class HMACSHA1Controller {
    @Autowired
    private HMACSHA1Service hmacsha1Service;

    /**
     * HMAC-SHA1签名生成接口
     * @param request 包含密钥、数据和编码格式的请求体
     * @return 签名结果响应对象
     * @apiNote 示例请求：{"key": "secret", "data": "message", "encoding": "hex"}
     */
    @PostMapping("/hash")
    public HMACSHA1Response hash(@RequestBody HMACSHA1Request request) {
        return hmacsha1Service.hash(request.getKey(),request.getData(), request.getEncoding());
    }
}
