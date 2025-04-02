package com.example.cryptographic_library.controller.hash;

import com.example.cryptographic_library.dto.hash.RIPEMD160Request;
import com.example.cryptographic_library.dto.hash.RIPEMD160Response;
import com.example.cryptographic_library.service.hash.RIPEMD160Service;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

/**
 * RIPEMD-160哈希计算接口
 *
 * <p>提供符合ISO/IEC 10118-3:2004标准的160位哈希计算服务</p>
 */
@RestController
@RequestMapping("/api/ripemd160")
@CrossOrigin(origins = "http://localhost:3000")
public class RIPEMD160Controller {

    @Autowired
    private RIPEMD160Service ripemd160Service;

    /**
     * 计算RIPEMD-160哈希值
     * @param request 包含原始数据和输出编码的请求体
     * @return 哈希计算结果响应
     * @apiNote 示例请求：{"data": "hello", "outputEncoding": "hex"}
     */
    @PostMapping("/hash")
    public RIPEMD160Response computeHash(@RequestBody RIPEMD160Request request) {
        return ripemd160Service.hash(request.getData(), request.getOutputEncoding());
    }
}
