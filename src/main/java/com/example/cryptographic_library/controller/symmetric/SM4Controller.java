package com.example.cryptographic_library.controller.symmetric;

import com.example.cryptographic_library.dto.symmetric.SM4Request;
import com.example.cryptographic_library.dto.symmetric.SM4Response;
import com.example.cryptographic_library.service.symmetric.SM4Service;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/sm4")
@CrossOrigin(origins = "http://localhost:3000") // 允许React前端访问
public class SM4Controller {

    @Autowired
    private SM4Service sm4Service;

    @PostMapping("/encrypt")
    public SM4Response encrypt(@RequestBody SM4Request request) {
        return sm4Service.encrypt(request.getKey(), request.getData(), request.getEncoding());
    }

    @PostMapping("/decrypt")
    public SM4Response decrypt(@RequestBody SM4Request request) {
        return sm4Service.decrypt(request.getKey(), request.getData(), request.getEncoding());
    }
}