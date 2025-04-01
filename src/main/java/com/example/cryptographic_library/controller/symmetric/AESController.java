package com.example.cryptographic_library.controller.symmetric;

import com.example.cryptographic_library.dto.symmetric.AESRequest;
import com.example.cryptographic_library.dto.symmetric.AESResponse;
import com.example.cryptographic_library.service.symmetric.AESService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/aes")
@CrossOrigin(origins = "http://localhost:3000")
public class AESController {

    @Autowired
    private AESService aesService;

    @PostMapping("/encrypt")
    public AESResponse encrypt(@RequestBody AESRequest request) {
        return aesService.encrypt(request.getKey(), request.getData(), request.getOutputEncoding());
    }
    @PostMapping("/decrypt")
    public AESResponse decrypt(@RequestBody AESRequest request) {
        return aesService.decrypt(request.getKey(), request.getData(), request.getOutputEncoding());
    }
}