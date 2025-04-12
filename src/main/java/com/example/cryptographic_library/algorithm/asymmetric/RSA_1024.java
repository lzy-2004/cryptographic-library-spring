package com.example.cryptographic_library.algorithm.asymmetric;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

import com.example.cryptographic_library.algorithm.encode.Base64;
import com.example.cryptographic_library.algorithm.encode.UTF_8;


public class RSA_1024 {
    private static final int KEY_SIZE = 1024;

    // RSA密钥对容器（使用自定义Base64序列化）
    public static class RSAKeyPair {
        private final BigInteger privateKey;
        private final BigInteger publicKey;
        private final BigInteger modulus;

        public BigInteger getPrivateKey() {
            return privateKey;
        }

        public BigInteger getPublicKey() {
            return publicKey;
        }

        public BigInteger getModulus() {
            return modulus;
        }

        public RSAKeyPair(BigInteger publicKey, BigInteger privateKey, BigInteger modulus) {
            this.publicKey = publicKey;
            this.privateKey = privateKey;
            this.modulus = modulus;
        }

        // 使用自定义Base64序列化
        public String serializePublicKey() {
            return Base64.encode(publicKey.toByteArray());

        }

        public String serializePrivateKey() {
            return Base64.encode(privateKey.toByteArray());
        }

        public String serializeModules() {
            return Base64.encode(modulus.toByteArray());
        }
    }

    /**
     * 生成RSA密钥对
     */
    public static RSAKeyPair generateKeyPair() {
        SecureRandom random = new SecureRandom();
        // 生成两个大素数（使用标准库的素数生成）
        BigInteger p = BigInteger.probablePrime(KEY_SIZE / 2, random);
        BigInteger q;
        do {
            q = BigInteger.probablePrime(KEY_SIZE / 2, random);
        } while (p.subtract(q).abs().bitLength() < KEY_SIZE / 4); // 安全素数间隔
        // 计算模数
        BigInteger n = p.multiply(q);
        // 计算欧拉函数
        BigInteger phi = p.subtract(BigInteger.ONE)
                .multiply(q.subtract(BigInteger.ONE));

        BigInteger e;
        do {
            e = BigInteger.probablePrime(1024, random); // 生成1024位随机素数
        } while (
                e.compareTo(phi) >= 0 ||          // e必须小于φ(n)
                        !e.gcd(phi).equals(BigInteger.ONE) // 必须满足e与φ(n)互质
        );
        // 计算私钥指数
        BigInteger d = e.modInverse(phi);
        return new RSAKeyPair(e, d, n);
    }

    /**
     * RSA加密（无填充基础版本）
     *
     * @param plaintext 明文字节数组（需自行处理填充）
     */
    public static byte[] encrypt(byte[] plaintext, BigInteger publicKey, BigInteger modulus) {
        int maxLength = modulus.bitLength() / 8 - 11; // 1024位密钥为117 字节
        byte[] padded = addPKCS1Padding(plaintext, maxLength + 11);
        BigInteger m = new BigInteger(1, padded);
        return m.modPow(publicKey, modulus).toByteArray();
    }

    /**
     * RSA解密（无填充基础版本）
     */
    public static byte[] decrypt(byte[] ciphertext, BigInteger privateKey, BigInteger modulus) {
        BigInteger c = new BigInteger(1, ciphertext);
        byte[] padded = c.modPow(privateKey, modulus).toByteArray();
        // 查找分隔符0x00
        int separator = -1;
        for (int i = 2; i < padded.length; i++) {
            if (padded[i] == 0x00) {
                separator = i;
                break;
            }
        }
        if (separator == -1) throw new IllegalArgumentException("无效填充");
        return Arrays.copyOfRange(padded, separator + 1, padded.length);
    }

    // PKCS#1 v1.5填充实现
    public static byte[] addPKCS1Padding(byte[] data, int blockSize) {
        if (data.length > blockSize - 11) {
            throw new IllegalArgumentException("明文过长");
        }

        byte[] padded = new byte[blockSize];
        padded[0] = 0x00;
        padded[1] = 0x02; // 随机填充类型

        SecureRandom random = new SecureRandom();
        // 填充随机非零字节
        for (int i = 2; i < blockSize - data.length - 1; i++) {
            byte randomByte;
            do {
                randomByte = (byte) random.nextInt();
            } while (randomByte == 0);
            padded[i] = randomByte;
        }

        padded[blockSize - data.length - 1] = 0x00;
        System.arraycopy(data, 0, padded, blockSize - data.length, data.length);
        return padded;
    }


    // 测试用例
    public static void main(String[] args) {
        // 生成密钥对
        System.out.println("生成RSA-1024密钥对...");
        RSAKeyPair keyPair = generateKeyPair();

        // 输出密钥信息
        System.out.println("\n=== 公钥信息 ===");
        System.out.println("模数长度: " + keyPair.modulus.bitLength() + " bits");
        System.out.println("Base64序列化公钥: ");
        System.out.println(keyPair.serializePublicKey());

        System.out.println("\n=== 私钥信息 ===");
        System.out.println("Base64序列化私钥: ");
        System.out.println(keyPair.serializePrivateKey());

        // 测试消息
        String message = "你好世界123aaa";
        byte[] data = UTF_8.encode(message);

        // 显示原始内容
        System.out.println("\n=== 加密测试 ===");
        System.out.println("原始明文: " + message);
        System.out.println("明文长度: " + data.length + " bytes");
        System.out.println("明文HEX: " + bytesToHex(data));

        // 加密测试
        byte[] ciphertext = encrypt(data, keyPair.publicKey, keyPair.modulus);
        System.out.println("\n加密结果长度: " + ciphertext.length + " bytes");
        System.out.println("密文Base64: " + Base64.encode(ciphertext));
        System.out.println("密文HEX: " + bytesToHex(ciphertext));

        // 解密测试
        byte[] decrypted = decrypt(ciphertext, keyPair.privateKey, keyPair.modulus);
        System.out.println("\n=== 解密结果 ===");
        System.out.println("解密后明文: " + UTF_8.decode(decrypted));
        System.out.println("解密验证结果: " + message.equals(UTF_8.decode(decrypted)));
    }

    // 字节数组转HEX字符串
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

}
