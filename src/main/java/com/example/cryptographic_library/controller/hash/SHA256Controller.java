package com.example.cryptographic_library.controller.hash;

import com.example.cryptographic_library.dto.hash.SHA256Request;
import com.example.cryptographic_library.dto.hash.SHA256Response;
import com.example.cryptographic_library.service.hash.SHA256Service;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

/**
 * SHA-256哈希计算接口
 *
 * <p>提供符合FIPS 180-4标准的256位安全哈希算法，采用Merkle-Damgård结构实现</p>
 *
 * <strong>安全推荐：</strong>SHA-256是NIST标准化算法，广泛用于数字签名、证书校验等安全场景
 */
@RestController
@RequestMapping("/api/sha256")
@CrossOrigin(origins = "http://localhost:3000")
public class SHA256Controller {

    @Autowired
    private SHA256Service sha256Service;

    /**
     * 计算SHA-256哈希值
     * @param request 包含原始数据和输出编码的请求体
     * @return 哈希计算结果响应（固定32 字节）
     * @apiNote 示例请求：{"data": "secure data", "encoding": "hex"}
     */
    @PostMapping("/hash")
    public SHA256Response hash(@RequestBody SHA256Request request) {
        return sha256Service.hash(request.getData(), request.getEncoding());
    }
}
