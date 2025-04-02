package com.example.cryptographic_library.controller.hash;

import com.example.cryptographic_library.dto.hash.PBKDF2Request;
import com.example.cryptographic_library.dto.hash.PBKDF2Response;
import com.example.cryptographic_library.service.hash.PBKDF2Service;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

/**
 * PBKDF2密钥派生接口
 *
 * <p>基于RFC 2898标准实现，使用HMAC-SHA256作为伪随机函数</p>
 */
@RestController
@RequestMapping("/api/pbkdf2")
@CrossOrigin(origins = "http://localhost:3000")
public class PBKDF2Controller {

    @Autowired
    private PBKDF2Service pbkdf2Service;

    /**
     * 密钥派生接口
     * @param request 包含密码、盐值、迭代次数等参数的请求体
     * @return 派生密钥结果响应
     * @apiNote 示例请求：
     * {
     *   "password": "myPassword123",
     *   "salt": "base64SaltString",
     *   "iterations": 10000,
     *   "keyLength": 32,
     *   "outputEncoding": "hex"
     * }
     */
    @PostMapping("/encrypt")
    public PBKDF2Response deriveKey(@RequestBody PBKDF2Request request) {
        return pbkdf2Service.deriveKey(
                request.getPassword(),
                request.getSalt(),
                request.getIterations(),
                request.getKeyLength(),
                request.getOutputEncoding()
        );
    }
}
