package com.example.cryptographic_library.controller.asymmetric;

import com.example.cryptographic_library.dto.asymmetric.ECDSADTO;
import com.example.cryptographic_library.service.asymmetric.ECDSAService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/ecdsa")
@CrossOrigin(origins = "http://localhost:3000")
public class ECDSAController {

    private final ECDSAService ecdsaService;

    public ECDSAController(ECDSAService ecdsaService) {
        this.ecdsaService = ecdsaService;
    }

    @GetMapping("/keypair")
    public ResponseEntity<ECDSADTO.KeyPairResponse> generateKeyPair() {
        return ResponseEntity.ok(ecdsaService.generateKeyPair());
    }

    @PostMapping("/sign")
    public ResponseEntity<ECDSADTO.SignResponse> sign(
            @RequestBody ECDSADTO.SignRequest request) {
        return ResponseEntity.ok(ecdsaService.sign(request));
    }

    @PostMapping("/verify")
    public ResponseEntity<ECDSADTO.VerifyResponse> verify(
            @RequestBody ECDSADTO.VerifyRequest request) {
        return ResponseEntity.ok(ecdsaService.verify(request));
    }
}
