package com.example.cryptographic_library.algorithm.asymmetric;


import com.example.cryptographic_library.algorithm.encode.Base64;
import com.example.cryptographic_library.algorithm.encode.UTF_8;
import com.example.cryptographic_library.algorithm.hash.SHA1;


import java.math.BigInteger;
import java.util.Arrays;

public class RSA_SHA1 {
    public static RSA_1024.RSAKeyPair generateKeyPair() {
        RSA_1024.RSAKeyPair keyPair = RSA_1024.generateKeyPair();
        return new RSA_1024.RSAKeyPair(keyPair.getPublicKey(), keyPair.getPrivateKey(), keyPair.getModulus());
    }


    private static byte[] addSignaturePadding(byte[] hash, BigInteger modulus) {
        byte[] digestInfo = new byte[] {
                0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14
        };

        int emLen = (modulus.bitLength() + 7) / 8;
        byte[] padded = new byte[emLen];
        padded[0] = 0x00;
        padded[1] = 0x01;

        int psLen = emLen - digestInfo.length - hash.length - 3;
        Arrays.fill(padded, 2, 2 + psLen, (byte)0xFF);
        padded[2 + psLen] = 0x00;

        System.arraycopy(digestInfo, 0, padded, 3 + psLen, digestInfo.length);
        System.arraycopy(hash, 0, padded, 3 + psLen + digestInfo.length, hash.length);

        return padded;
    }

    public static String sign(String message,BigInteger privateKey,BigInteger modulus) {
        byte[] hash = SHA1.hash(UTF_8.encode(message));
        byte[] paddedHash = addSignaturePadding(hash,modulus);

        BigInteger m = new BigInteger(1, paddedHash);
        BigInteger signature = m.modPow(privateKey, modulus);

        return Base64.encode(signature.toByteArray());
    }

    public static boolean verify(String message, String signatureBase64, BigInteger publicKey, BigInteger modulus) {
        try {
            byte[] hash = SHA1.hash(UTF_8.encode(message));
            byte[] signature = Base64.decode(signatureBase64);

            // 检查签名长度
            int keyLengthBytes = (modulus.bitLength() + 7) / 8;
            if (signature.length > keyLengthBytes + 1) {
                return false; // 签名长度异常
            }

            BigInteger s = new BigInteger(1, signature);
            
            // 检查签名范围
            if (s.compareTo(BigInteger.ZERO) <= 0 || s.compareTo(modulus) >= 0) {
                return false; // 签名值超出有效范围
            }
            
            // 解密签名
            byte[] decrypted = s.modPow(publicKey, modulus).toByteArray();
            
            // 规范化解密结果以匹配预期的填充长度
            decrypted = normalizeToLength(decrypted, keyLengthBytes);
            
            // 如果长度不匹配，验证失败
            if (decrypted == null) {
                return false;
            }
            
            // 验证PKCS#1 v1.5填充格式
            if (!validatePKCS1Type1Padding(decrypted)) {
                return false;
            }
            
            // 计算预期的填充数据
            byte[] expectedPadded = addSignaturePadding(hash, modulus);
            
            // 使用恒定时间比较以防止时序攻击
            return constantTimeEquals(decrypted, expectedPadded);
        } catch (Exception e) {
            // 捕获任何异常并返回验证失败
            return false;
        }
    }

    /**
     * 验证PKCS#1 v1.5 Type 1填充格式
     * 格式为: 0x00 0x01 0xFF...0xFF 0x00 [digestInfo+hash]
     */
    private static boolean validatePKCS1Type1Padding(byte[] data) {
        // 检查基本长度
        if (data.length < 11) { // 最小长度: 0x00 0x01 8字节PS 0x00 至少1字节数据
            return false;
        }
        
        // 检查头部标记
        if (data[0] != 0x00 || data[1] != 0x01) {
            return false;
        }
        
        // 查找分隔符0x00
        int separatorIndex = -1;
        for (int i = 2; i < data.length; i++) {
            if (data[i] == 0x00) {
                separatorIndex = i;
                break;
            }
            
            // 检查填充字节，必须是0xFF
            if (data[i] != (byte)0xFF) {
                return false;
            }
        }
        
        // 必须找到分隔符，且不能紧跟在块类型后面
        return separatorIndex > 2 && separatorIndex < data.length - 1;
    }

    /**
     * 将字节数组规范化为指定长度
     */
    private static byte[] normalizeToLength(byte[] data, int targetLength) {
        if (data.length == targetLength) {
            return data;
        }
        
        if (data.length == targetLength + 1 && data[0] == 0) {
            // 处理BigInteger可能添加的前导零
            return Arrays.copyOfRange(data, 1, data.length);
        }
        
        if (data.length < targetLength) {
            // 填充前导零使长度匹配
            byte[] result = new byte[targetLength];
            System.arraycopy(data, 0, result, targetLength - data.length, data.length);
            return result;
        }
        
        // 长度不符合要求
        return null;
    }

    /**
     * 恒定时间比较两个字节数组，防止时序攻击
     */
    private static boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a.length != b.length) {
            return false;
        }
        
        int result = 0;
        for (int i = 0; i < a.length; i++) {
            result |= a[i] ^ b[i]; // 按位异或，任何差异都将使result非零
        }
        
        return result == 0;
    }

    public static void main(String[] args) {
        RSA_1024.RSAKeyPair keyPair =generateKeyPair();
        System.out.println("公钥: " + keyPair.serializePublicKey());

        String message = "重要数据：转账100万元";
        String signature = sign(message, keyPair.getPrivateKey(), keyPair.getModulus());

        System.out.println("消息: " + message);
        System.out.println("签名: " + signature);
        System.out.println("验证结果: " + verify(message, signature, keyPair.getPublicKey(), keyPair.getModulus()));
        
        // 测试被篡改的签名
        if (signature.length() > 2) {
            String tampered = signature.substring(0, signature.length()-2) + "AB";
            System.out.println("被篡改的签名: " + tampered);
            System.out.println("篡改后验证结果: " + verify(message, tampered, keyPair.getPublicKey(), keyPair.getModulus()));
        }
    }
}


