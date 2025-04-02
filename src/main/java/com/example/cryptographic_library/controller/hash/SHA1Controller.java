package com.example.cryptographic_library.controller.hash;

import com.example.cryptographic_library.dto.hash.SHA1Request;
import com.example.cryptographic_library.dto.hash.SHA1Response;
import com.example.cryptographic_library.service.hash.SHA1Service;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

/**
 * SHA-1哈希计算接口
 *
 * <p>提供符合FIPS 180-4标准的160位哈希计算服务</p>
 *
 * <strong>安全提示：</strong>SHA-1已不适用于安全敏感场景，建议使用SHA-256等更强算法
 */
@RestController
@RequestMapping("/api/sha1")
@CrossOrigin(origins = "http://localhost:3000")
public class SHA1Controller {
    @Autowired
    private SHA1Service sha1Service;

    /**
     * 计算SHA-1哈希值
     * @param request 包含原始数据和输出编码的请求体
     * @return 哈希计算结果响应（固定20 字节）
     * @apiNote 示例请求：{"data": "test", "encoding": "hex"}
     */
    @PostMapping("/hash")
    public SHA1Response hash(@RequestBody SHA1Request request) {
        return sha1Service.hash(request.getData(), request.getEncoding());
    }
}
