package com.example.cryptographic_library.controller.hash;

import com.example.cryptographic_library.dto.hash.RIPEMD160Request;
import com.example.cryptographic_library.dto.hash.RIPEMD160Response;
import com.example.cryptographic_library.service.hash.RIPEMD160Service;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/ripemd160")
@CrossOrigin(origins = "http://localhost:3000")
public class RIPEMD160Controller {

    @Autowired
    private RIPEMD160Service ripemd160Service;

    @PostMapping("/hash")
    public RIPEMD160Response computeHash(@RequestBody RIPEMD160Request request) {
        return ripemd160Service.hash(request.getData(), request.getOutputEncoding());
    }
}
