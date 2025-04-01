package com.example.cryptographic_library.controller.hash;

import com.example.cryptographic_library.dto.hash.SHA3_512Request;
import com.example.cryptographic_library.dto.hash.SHA3_512Response;
import com.example.cryptographic_library.service.hash.SHA3_512Service;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/sha3-512")
@CrossOrigin(origins = "http://localhost:3000")
public class SHA3_512Controller {

    @Autowired
    private SHA3_512Service sha3_512Service;

    @PostMapping("/hash")
    public SHA3_512Response computeHash(@RequestBody SHA3_512Request request) {
        return sha3_512Service.hash(request.getData(), request.getEncoding());
    }
}
