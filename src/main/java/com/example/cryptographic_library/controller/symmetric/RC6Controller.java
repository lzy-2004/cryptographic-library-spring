package com.example.cryptographic_library.controller.symmetric;

import com.example.cryptographic_library.dto.symmetric.RC6Request;
import com.example.cryptographic_library.dto.symmetric.RC6Response;
import com.example.cryptographic_library.service.symmetric.RC6Service;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/rc6")
@CrossOrigin(origins = "http://localhost:3000")
public class RC6Controller {

    @Autowired
    private RC6Service rc6Service;

    @PostMapping("/encrypt")
    public RC6Response process(@RequestBody RC6Request request) {
        return rc6Service.encrypt(request.getKey(), request.getData(), request.getOutputEncoding());
    }
    @PostMapping("/decrypt")
    public RC6Response decrypt(@RequestBody RC6Request request) {
        return rc6Service.decrypt(request.getKey(), request.getData(), request.getOutputEncoding());
    }
}
