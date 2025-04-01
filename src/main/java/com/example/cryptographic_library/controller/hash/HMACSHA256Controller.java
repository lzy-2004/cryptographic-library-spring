package com.example.cryptographic_library.controller.hash;

import com.example.cryptographic_library.dto.hash.HMACSHA256Request;
import com.example.cryptographic_library.dto.hash.HMACSHA256Response;
import com.example.cryptographic_library.service.hash.HMACSHA256Service;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/hmacsha256")
@CrossOrigin(origins = "http://localhost:3000")
public class HMACSHA256Controller {
    @Autowired
    private HMACSHA256Service hmacsha256Service;

    @PostMapping("/hash")
    public HMACSHA256Response hash(@RequestBody HMACSHA256Request request) {
        return hmacsha256Service.hash(request.getKey(),request.getData(), request.getEncoding());
    }
}
