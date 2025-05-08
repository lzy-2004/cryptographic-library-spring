package com.example.cryptographic_library.controller.hash;

import com.example.cryptographic_library.dto.hash.MD5Request;
import com.example.cryptographic_library.dto.hash.MD5Response;
import com.example.cryptographic_library.service.hash.MD5Service;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/md5")
@CrossOrigin(origins = "http://localhost:3000")
public class MD5Controller {
    @Autowired
    private MD5Service md5Service;

    @PostMapping("/hash")
    public MD5Response hash(@RequestBody MD5Request request) {
        return md5Service.hash(request.getData(), request.getEncoding());
    }
}
