package com.example.cryptographic_library.controller.asymmetric;

import com.example.cryptographic_library.dto.asymmetric.RSA1024KeyPair;
import com.example.cryptographic_library.dto.asymmetric.RSA1024Request;
import com.example.cryptographic_library.dto.asymmetric.RSA1024Response;
import com.example.cryptographic_library.service.asymmetric.RSA1024Service;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/rsa1024")
@CrossOrigin(origins = "http://localhost:3000")
public class RSA1024Controller {
    @Autowired
    private RSA1024Service service;
    @GetMapping("/keypair")
    public RSA1024KeyPair generateKeyPair(){
        return service.generateKeyPair();
    }
    @PostMapping("/encrypt")
    public RSA1024Response encrypt(@RequestBody RSA1024Request request){
        return service.encrypt(request);
    }
    @PostMapping("/decrypt")
    public RSA1024Response decrypt(@RequestBody RSA1024Request request){
        return service.decrypt(request);
    }
}
