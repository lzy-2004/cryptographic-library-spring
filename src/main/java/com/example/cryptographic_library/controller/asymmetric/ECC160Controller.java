package com.example.cryptographic_library.controller.asymmetric;

import com.example.cryptographic_library.dto.asymmetric.ECC160DTO;
import com.example.cryptographic_library.service.asymmetric.ECC160Service;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/ecc160")
@CrossOrigin(origins = "http://localhost:3000")
public class ECC160Controller {
    private final ECC160Service cryptoService;

    public ECC160Controller(ECC160Service cryptoService) {
        this.cryptoService = cryptoService;
    }

    @GetMapping("/keypair")
    public ResponseEntity<ECC160DTO.KeyPairResponse> generateKeyPair() {
        return ResponseEntity.ok(cryptoService.generateKeyPair());
    }

    @PostMapping("/encrypt")
    public ResponseEntity<ECC160DTO.CryptoResponse> encrypt(
            @RequestBody ECC160DTO.EncryptRequest request) {
        return ResponseEntity.ok(cryptoService.encrypt(request));
    }

    @PostMapping("/decrypt")
    public ResponseEntity<ECC160DTO.CryptoResponse> decrypt(
            @RequestBody ECC160DTO.DecryptRequest request) {
        return ResponseEntity.ok(cryptoService.decrypt(request));
    }
}
