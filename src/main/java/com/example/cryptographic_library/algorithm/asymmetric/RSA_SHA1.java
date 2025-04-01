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
        byte[] hash = SHA1.hash(UTF_8.encode(message));
        byte[] signature = Base64.decode(signatureBase64);

        BigInteger s = new BigInteger(1, signature);
        byte[] decrypted = s.modPow(
                publicKey,
                modulus
        ).toByteArray();

        byte[] expectedPadded = addSignaturePadding(hash,modulus);
        return Arrays.equals(normalizeBytes(decrypted), normalizeBytes(expectedPadded));
    }

    private static byte[] normalizeBytes(byte[] data) {
        if (data.length > 0 && data[0] == 0) {
            return Arrays.copyOfRange(data, 1, data.length);
        }
        return data;
    }

    public static void main(String[] args) {
        RSA_1024.RSAKeyPair keyPair =generateKeyPair();
        System.out.println("公钥: " + keyPair.serializePublicKey());

        String message = "重要数据：转账100万元";
        String signature = sign(message, keyPair.getPrivateKey(), keyPair.getModulus());

        System.out.println("消息: " + message);
        System.out.println("签名: " + signature);
        System.out.println("验证结果: " + verify(message, signature, keyPair.getPublicKey(), keyPair.getModulus()));
    }
}


