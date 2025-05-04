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
        try {
            // 验证请求参数
            if (request.getData() == null || request.getData().isEmpty()) {
                return new RSASHA1ResponseSign(-1, "加密失败: 待签名数据不能为空", null);
            }
            
            if (request.getPrivateKey() == null || request.getModulus() == null) {
                return new RSASHA1ResponseSign(-1, "加密失败: 私钥或模数不能为空", null);
            }
            
            RSA_SHA1 rsasha1 = new RSA_SHA1();
            BigInteger privateKey = base64ToBigInteger(request.getPrivateKey());
            BigInteger modulus = base64ToBigInteger(request.getModulus());
            
            // 检查密钥有效性
            if (privateKey.compareTo(BigInteger.ZERO) <= 0 || privateKey.compareTo(modulus) >= 0) {
                return new RSASHA1ResponseSign(-1, "加密失败: 私钥无效", null);
            }
            
            String signature = rsasha1.sign(request.getData(), privateKey, modulus);
            return new RSASHA1ResponseSign(0, "加密成功", signature);
        } catch (IllegalArgumentException e) {
            return new RSASHA1ResponseSign(-1, "加密失败: Base64解码错误 - " + e.getMessage(), null);
        } catch (Exception e) {
            return new RSASHA1ResponseSign(-1, "加密失败: " + e.getMessage(), null);
        }
    }

    public RSASHA1ResponseVerify verify(RSASHA1RequestVerify request) {
        try {
            // 验证请求参数
            if (request.getData() == null || request.getData().isEmpty()) {
                return new RSASHA1ResponseVerify(-1, "验证失败: 待验证数据不能为空", false);
            }
            
            if (request.getSignature() == null || request.getSignature().isEmpty()) {
                return new RSASHA1ResponseVerify(-1, "验证失败: 签名不能为空", false);
            }
            
            if (request.getPublicKey() == null || request.getModulus() == null) {
                return new RSASHA1ResponseVerify(-1, "验证失败: 公钥或模数不能为空", false);
            }
            
            RSA_SHA1 rsasha1 = new RSA_SHA1();
            BigInteger publicKey = base64ToBigInteger(request.getPublicKey());
            BigInteger modulus = base64ToBigInteger(request.getModulus());
            
            // 检查密钥有效性
            if (publicKey.compareTo(BigInteger.ZERO) <= 0 || publicKey.compareTo(modulus) >= 0) {
                return new RSASHA1ResponseVerify(-1, "验证失败: 公钥无效", false);
            }
            
            boolean result = rsasha1.verify(request.getData(), request.getSignature(), publicKey, modulus);
            if (result) {
                return new RSASHA1ResponseVerify(0, "验证成功: 签名有效", true);
            } else {
                return new RSASHA1ResponseVerify(0, "验证成功: 签名无效", false);
            }
        } catch (IllegalArgumentException e) {
            return new RSASHA1ResponseVerify(-1, "验证失败: Base64解码错误 - " + e.getMessage(), false);
        } catch (Exception e) {
            return new RSASHA1ResponseVerify(-1, "验证失败: " + e.getMessage(), false);
        }
    }
    
    public BigInteger base64ToBigInteger(String base64) {
        try {
            byte[] decoded = Base64.decode(base64);
            if (decoded.length == 0) {
                throw new IllegalArgumentException("Base64解码后数据为空");
            }
            return new BigInteger(1, decoded); // 始终使用正数解析
        } catch (Exception e) {
            throw new IllegalArgumentException("Base64转BigInteger失败: " + e.getMessage());
        }
    }
}
