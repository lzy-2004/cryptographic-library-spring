package com.example.cryptographic_library.controller.encode;

import com.example.cryptographic_library.dto.encode.HexRequest;
import com.example.cryptographic_library.dto.encode.HexResponse;
import com.example.cryptographic_library.service.encode.HexService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/hex")
@CrossOrigin(origins = "http://localhost:3000")
public class HexController {
    @Autowired
    private HexService hexService;

    @PostMapping("/encode")
    public HexResponse encode(@RequestBody HexRequest request) {
        return hexService.encode(request.getData());
    }

    @PostMapping("/decode")
    public HexResponse decode(@RequestBody HexRequest request) {
        return hexService.decode(request.getData());
    }
}
