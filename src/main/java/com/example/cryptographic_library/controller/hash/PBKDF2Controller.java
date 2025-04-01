package com.example.cryptographic_library.controller.hash;

import com.example.cryptographic_library.dto.hash.PBKDF2Request;
import com.example.cryptographic_library.dto.hash.PBKDF2Response;
import com.example.cryptographic_library.service.hash.PBKDF2Service;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/pbkdf2")
@CrossOrigin(origins = "http://localhost:3000")
public class PBKDF2Controller {

    @Autowired
    private PBKDF2Service pbkdf2Service;

    @PostMapping("/encrypt")
    public PBKDF2Response deriveKey(@RequestBody PBKDF2Request request) {
        return pbkdf2Service.deriveKey(
                request.getPassword(),
                request.getSalt(),
                request.getIterations(),
                request.getKeyLength(),
                request.getOutputEncoding()
        );
    }
}
