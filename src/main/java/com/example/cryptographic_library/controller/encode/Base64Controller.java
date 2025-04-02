package com.example.cryptographic_library.controller.encode;

import com.example.cryptographic_library.dto.encode.Base64Request;
import com.example.cryptographic_library.dto.encode.Base64Response;
import com.example.cryptographic_library.service.encode.Base64Service;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

/**
 * Base64编解码REST接口
 *
 * <p>提供标准的Base64编码/解码能力，支持跨域请求</p>
 */
@RestController
@RequestMapping("/api/base64")
@CrossOrigin(origins = "http://localhost:3000")
public class Base64Controller {
    @Autowired
    private Base64Service base64Service;

    /**
     * Base64编码接口
     * @param request 编码请求参数（JSON格式）
     * @return 包含状态码、消息和编码结果的响应对象
     * @apiNote 示例请求：{"data": "Hello World"}
     */
    @PostMapping("/encode")
    public Base64Response encode(@RequestBody Base64Request request) {
        return base64Service.encode(request.getData());
    }
    /**
     * Base64解码接口
     * @param request 解码请求参数（JSON格式）
     * @return 包含状态码、消息和解码结果的响应对象
     * @throws IllegalArgumentException 当输入非标准Base64字符串时返回状态码-2
     * @apiNote 示例请求：{"data": "SGVsbG8gV29ybGQh"}
     */
    @PostMapping("/decode")
    public Base64Response decode(@RequestBody Base64Request request) {
        return base64Service.decode(request.getData());
    }
}
