package com.example.cryptographic_library.service.asymmetric;

import com.example.cryptographic_library.algorithm.asymmetric.RSA_1024;
import com.example.cryptographic_library.algorithm.asymmetric.RSA_SHA1;
import com.example.cryptographic_library.algorithm.encode.Base64;
import com.example.cryptographic_library.dto.asymmetric.*;
import org.springframework.stereotype.Service;

import java.math.BigInteger;

@Service
public class RSASHA1Service {
    public RSA1024KeyPair generateKeyPair() {
        RSA_SHA1 rsasha1 = new RSA_SHA1();
        RSA_1024.RSAKeyPair keyPair = rsasha1.generateKeyPair();
        return new RSA1024KeyPair(keyPair.serializePublicKey(), keyPair.serializePrivateKey(), keyPair.serializeModules());
    }
    public RSASHA1ResponseSign sign(RSASHA1RequestSign request) {
        try{
            RSA_SHA1 rsasha1 = new RSA_SHA1();
            String signature = rsasha1.sign(request.getData(), base64ToBigInteger(request.getPrivateKey()), base64ToBigInteger(request.getModulus()));
            return new RSASHA1ResponseSign(0, "加密成功", signature);
        }catch (Exception e){
            return new RSASHA1ResponseSign(-1, "加密失败: " + e.getMessage(), null);
        }
    }

    public RSASHA1ResponseVerify verify(RSASHA1RequestVerify request) {
        try{
            RSA_SHA1 rsasha1 = new RSA_SHA1();
            boolean result = rsasha1.verify(request.getData(), request.getSignature(), base64ToBigInteger(request.getPublicKey()), base64ToBigInteger(request.getModulus()));
            return new RSASHA1ResponseVerify(0, "验证成功", result);
        }catch (Exception e){
            return new RSASHA1ResponseVerify(-1, "验证失败: " + e.getMessage(), false);
        }
    }
    public BigInteger base64ToBigInteger(String base64) {
        byte[] decoded = Base64.decode(base64);
        return new BigInteger(decoded);
    }
}
