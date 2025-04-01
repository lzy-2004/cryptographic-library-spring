package com.example.cryptographic_library.service.asymmetric;

import com.example.cryptographic_library.algorithm.asymmetric.ECDSA;
import com.example.cryptographic_library.dto.asymmetric.ECDSADTO;
import org.springframework.stereotype.Service;
import java.util.Base64; // 修改导入

@Service
public class ECDSAService {

    public ECDSADTO.KeyPairResponse generateKeyPair() {
        ECDSA.KeyPair keyPair = ECDSA.generateKeyPair();
        return new ECDSADTO.KeyPairResponse(
                Base64.getEncoder().encodeToString(keyPair.publicKeyX), // 修改编码方式
                Base64.getEncoder().encodeToString(keyPair.publicKeyY),
                Base64.getEncoder().encodeToString(keyPair.privateKey)
        );
    }

    public ECDSADTO.SignResponse sign(ECDSADTO.SignRequest request) {
        byte[] privateKey = Base64.getDecoder().decode(request.getPrivateKey()); // 修改解码方式
        byte[] message = request.getMessage().getBytes();

        ECDSA.Signature signature = ECDSA.sign(privateKey, message);
        return new ECDSADTO.SignResponse(
                Base64.getEncoder().encodeToString(signature.r),
                Base64.getEncoder().encodeToString(signature.s)
        );
    }

    public ECDSADTO.VerifyResponse verify(ECDSADTO.VerifyRequest request) {
        try {
            ECDSA.KeyPair keyPair = new ECDSA.KeyPair(
                    Base64.getDecoder().decode(request.getPublicKeyX()),
                    Base64.getDecoder().decode(request.getPublicKeyY()),
                    new byte[0]
            );

            ECDSA.Signature signature = new ECDSA.Signature(
                    Base64.getDecoder().decode(request.getSignatureR()),
                    Base64.getDecoder().decode(request.getSignatureS())
            );

            boolean isValid = ECDSA.verify(keyPair,
                    request.getMessage().getBytes(),
                    signature);

            return new ECDSADTO.VerifyResponse(
                    isValid,
                    isValid ? "签名验证成功" : "签名验证失败"
            );
        } catch (Exception e) {
            return new ECDSADTO.VerifyResponse(
                    false,
                    "验证过程出错: " + e.getMessage()
            );
        }
    }
}
