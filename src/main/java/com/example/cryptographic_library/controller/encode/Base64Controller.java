package com.example.cryptographic_library.controller.encode;

import com.example.cryptographic_library.dto.encode.Base64Request;
import com.example.cryptographic_library.dto.encode.Base64Response;
import com.example.cryptographic_library.service.encode.Base64Service;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/base64")
@CrossOrigin(origins = "http://localhost:3000")
public class Base64Controller {
    @Autowired
    private Base64Service base64Service;

    @PostMapping("/encode")
    public Base64Response encode(@RequestBody Base64Request request) {
        return base64Service.encode(request.getData());
    }
    @PostMapping("/decode")
    public Base64Response decode(@RequestBody Base64Request request) {
        return base64Service.decode(request.getData());
    }
}
