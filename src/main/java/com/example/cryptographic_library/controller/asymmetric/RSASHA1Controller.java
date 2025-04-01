package com.example.cryptographic_library.controller.asymmetric;

import com.example.cryptographic_library.dto.asymmetric.*;
import com.example.cryptographic_library.service.asymmetric.RSASHA1Service;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/rsasha1")
@CrossOrigin(origins = "http://localhost:3000")
public class RSASHA1Controller {
    @Autowired
    private RSASHA1Service service;
    @GetMapping("/keypair")
    public RSA1024KeyPair generateKeyPair(){
        return service.generateKeyPair();
    }
    @PostMapping("/sign")
    public RSASHA1ResponseSign sign(@RequestBody RSASHA1RequestSign request){
        return service.sign(request);
    }
    @PostMapping("/verify")
    public RSASHA1ResponseVerify verify(@RequestBody RSASHA1RequestVerify request){
        return service.verify(request);
    }
}
