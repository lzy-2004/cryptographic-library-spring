package com.example.cryptographic_library.service.asymmetric;

import com.example.cryptographic_library.algorithm.asymmetric.RSA_1024;
import com.example.cryptographic_library.algorithm.encode.Base64;
import com.example.cryptographic_library.algorithm.encode.UTF_8;
import com.example.cryptographic_library.dto.asymmetric.RSA1024KeyPair;
import com.example.cryptographic_library.dto.asymmetric.RSA1024Request;
import com.example.cryptographic_library.dto.asymmetric.RSA1024Response;
import org.springframework.stereotype.Service;

import java.math.BigInteger;

@Service
public class RSA1024Service {
    public RSA1024KeyPair generateKeyPair() {
        RSA_1024 rsa = new RSA_1024();
        RSA_1024.RSAKeyPair keyPair = rsa.generateKeyPair();
        return new RSA1024KeyPair(keyPair.serializePublicKey(), keyPair.serializePrivateKey(), keyPair.serializeModules());
    }
    public RSA1024Response encrypt(RSA1024Request request) {
        try{
            RSA_1024 rsa = new RSA_1024();
            byte[] encrypted = rsa.encrypt(UTF_8.encode(request.getData()), base64ToBigInteger(request.getKey()), base64ToBigInteger(request.getModulus()));
            if(request.getEncoding().equals("base64")){
                return new RSA1024Response(0, "加密成功", Base64.encode(encrypted));
            }else{
                return new RSA1024Response(0, "加密成功", bytesToHex(encrypted));
            }
        }catch (Exception e){
            return new RSA1024Response(-1, "加密失败: " + e.getMessage(), null);
        }
    }

    public RSA1024Response decrypt(RSA1024Request request) {
        try{
            RSA_1024 rsa = new RSA_1024();
            byte[] decoded;
            if(request.getEncoding().equals("base64")){
                decoded = Base64.decode(request.getData());
            }else{
                decoded = hexToBytes(request.getData());
            }
            byte[] decrypted = rsa.decrypt(decoded, base64ToBigInteger(request.getKey()), base64ToBigInteger(request.getModulus()));
            return new RSA1024Response(0, "解密成功", UTF_8.decode(decrypted));
        }catch (Exception e){
            return new RSA1024Response(-1, "加密失败: " + e.getMessage(), null);
        }
    }
    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xFF));
        }
        return sb.toString();
    }
    private byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }
    public BigInteger base64ToBigInteger(String base64) {
        byte[] decoded = Base64.decode(base64);
        return new BigInteger(decoded);
    }
}
