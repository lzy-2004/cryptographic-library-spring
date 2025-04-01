package com.example.cryptographic_library.controller.hash;

import com.example.cryptographic_library.dto.hash.SHA256Request;
import com.example.cryptographic_library.dto.hash.SHA256Response;
import com.example.cryptographic_library.service.hash.SHA256Service;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/sha256")
@CrossOrigin(origins = "http://localhost:3000")
public class SHA256Controller {

    @Autowired
    private SHA256Service sha256Service;

    @PostMapping("/hash")
    public SHA256Response hash(@RequestBody SHA256Request request) {
        return sha256Service.hash(request.getData(), request.getEncoding());
    }
}
