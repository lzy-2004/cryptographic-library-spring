package com.example.cryptographic_library.controller.hash;

import com.example.cryptographic_library.dto.hash.HMACSHA1Request;
import com.example.cryptographic_library.dto.hash.HMACSHA1Response;
import com.example.cryptographic_library.service.hash.HMACSHA1Service;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/hmacsha1")
@CrossOrigin(origins = "http://localhost:3000")
public class HMACSHA1Controller {
    @Autowired
    private HMACSHA1Service hmacsha1Service;

    @PostMapping("/hash")
    public HMACSHA1Response hash(@RequestBody HMACSHA1Request request) {
        return hmacsha1Service.hash(request.getKey(),request.getData(), request.getEncoding());
    }
}
