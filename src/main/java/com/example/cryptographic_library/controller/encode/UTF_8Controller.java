package com.example.cryptographic_library.controller.encode;

import com.example.cryptographic_library.dto.encode.UTF_8Request;
import com.example.cryptographic_library.dto.encode.UTF_8Response;
import com.example.cryptographic_library.service.encode.UTF_8Service;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/utf-8")
@CrossOrigin(origins = "http://localhost:3000")
public class UTF_8Controller {
    @Autowired
    private UTF_8Service utf_8Service;

    @PostMapping("/encode")
    public UTF_8Response encode(@RequestBody UTF_8Request request) {
        return utf_8Service.encode(request.getData(),request.getEncoding());
    }
    @PostMapping("/decode")
    public UTF_8Response decode(@RequestBody UTF_8Request request) {
        return utf_8Service.decode(request.getData(),request.getEncoding());
    }
}
