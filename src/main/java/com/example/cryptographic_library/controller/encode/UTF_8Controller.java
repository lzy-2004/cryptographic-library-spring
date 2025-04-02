package com.example.cryptographic_library.controller.encode;

import com.example.cryptographic_library.dto.encode.UTF_8Request;
import com.example.cryptographic_library.dto.encode.UTF_8Response;
import com.example.cryptographic_library.service.encode.UTF_8Service;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

/**
 * UTF-8编解码REST接口
 *
 * <p>提供UTF-8编码格式与其他二进制表示形式（十六进制/二进制/八进制/十进制）的互转能力</p>
 */
@RestController
@RequestMapping("/api/utf-8")
@CrossOrigin(origins = "http://localhost:3000")
public class UTF_8Controller {
    @Autowired
    private UTF_8Service utf_8Service;

    /**
     * UTF-8编码接口
     * @param request 编码请求参数（需包含原始字符串和目标格式）
     * @return 包含状态码、消息和编码结果的响应对象
     * @apiNote 示例请求：{"data": "你好", "encoding": "hex"}
     */
    @PostMapping("/encode")
    public UTF_8Response encode(@RequestBody UTF_8Request request) {
        return utf_8Service.encode(request.getData(),request.getEncoding());
    }
    /**
     * UTF-8解码接口
     * @param request 解码请求参数（需包含编码数据和原始格式）
     * @return 包含状态码、消息和解码结果的响应对象
     * @throws IllegalArgumentException 当输入格式不匹配时返回状态码-2
     * @apiNote 示例请求：{"data": "e4bda0e5a5bd", "encoding": "hex"}
     */
    @PostMapping("/decode")
    public UTF_8Response decode(@RequestBody UTF_8Request request) {
        return utf_8Service.decode(request.getData(),request.getEncoding());
    }
}
