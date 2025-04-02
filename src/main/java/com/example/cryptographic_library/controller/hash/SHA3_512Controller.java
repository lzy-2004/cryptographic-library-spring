package com.example.cryptographic_library.controller.hash;

import com.example.cryptographic_library.dto.hash.SHA3_512Request;
import com.example.cryptographic_library.dto.hash.SHA3_512Response;
import com.example.cryptographic_library.service.hash.SHA3_512Service;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

/**
 * SHA3-512哈希计算接口
 *
 * <p>提供符合FIPS 202标准的512位安全哈希算法，采用Keccak海绵结构实现</p>
 *
 * <strong>安全推荐：</strong>SHA3-512是NIST标准化算法，适用于高安全性场景
 */
@RestController
@RequestMapping("/api/sha3-512")
@CrossOrigin(origins = "http://localhost:3000")
public class SHA3_512Controller {

    @Autowired
    private SHA3_512Service sha3_512Service;

    /**
     * 计算SHA3-512哈希值
     * @param request 包含原始数据和输出编码的请求体
     * @return 哈希计算结果响应（固定 64 字节）
     * @apiNote 示例请求：{"data": "sensitive data", "encoding": "base64"}
     */
    @PostMapping("/hash")
    public SHA3_512Response computeHash(@RequestBody SHA3_512Request request) {
        return sha3_512Service.hash(request.getData(), request.getEncoding());
    }
}
