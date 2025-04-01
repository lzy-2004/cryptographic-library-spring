package com.example.cryptographic_library.controller.hash;

import com.example.cryptographic_library.dto.hash.SHA1Request;
import com.example.cryptographic_library.dto.hash.SHA1Response;
import com.example.cryptographic_library.service.hash.SHA1Service;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/sha1")
@CrossOrigin(origins = "http://localhost:3000")
public class SHA1Controller {
    @Autowired
    private SHA1Service sha1Service;

    @PostMapping("/hash")
    public SHA1Response hash(@RequestBody SHA1Request request) {
        return sha1Service.hash(request.getData(), request.getEncoding());
    }
}
