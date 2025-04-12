package com.example.cryptographic_library.algorithm.asymmetric;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * ECC160椭圆曲线加密算法实现
 * 曲线参数：secp160r1 (160位安全级别)
 * 功能包含：密钥生成、加密、解密
 */
public class ECC_160 {
    // ------------------------ 椭圆曲线参数 ------------------------
    private static final BigInteger p = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFF", 16);
    private static final BigInteger a = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFC", 16);
    private static final BigInteger b = new BigInteger("1C97BEFC54BD7A8B65ACF89F81D4D4ADC565FA45", 16);
    private static final BigInteger n = new BigInteger("0100000000000000000001F4C8F927AED3CA752257", 16);
    private static final ECPoint G = new ECPoint(
            new BigInteger("4A96B5688EF573284664698968C38BB913CBFC82", 16),
            new BigInteger("23A628553168947D59DCC912042351377AC5FB32", 16)
    );

    // ------------------------ 数据结构定义 ------------------------
    public static class ECPoint {
        public final BigInteger x;
        public final BigInteger y;

        public ECPoint(BigInteger x, BigInteger y) {
            this.x = x;
            this.y = y;
        }

        public boolean isInfinity() {
            return x == null || y == null;
        }

        @Override
        public String toString() {
            return isInfinity() ? "INF" : String.format("(%s,%s)", x.toString(16), y.toString(16));
        }
    }

    public static class KeyPair {
        public final byte[] publicKey;
        public final byte[] privateKey;

        public KeyPair(byte[] publicKey, byte[] privateKey) {
            this.publicKey = publicKey;
            this.privateKey = privateKey;
        }
    }

    public static class Ciphertext {
        public final byte[] ephemeralPubKey;
        public final byte[] encryptedData;

        public Ciphertext(byte[] ephemeralPubKey, byte[] encryptedData) {
            this.ephemeralPubKey = ephemeralPubKey;
            this.encryptedData = encryptedData;
        }
    }

    // ------------------------ 核心算法实现 ------------------------

    /**
     * 椭圆曲线点加法
     */
    private static ECPoint pointAdd(ECPoint p1, ECPoint p2) {
        if (p1.isInfinity()) return p2;
        if (p2.isInfinity()) return p1;

        BigInteger lambda;
        if (p1.x.equals(p2.x)) {
            if (p1.y.equals(p2.y)) {
                // 点倍乘
                BigInteger numerator = p1.x.pow(2).multiply(BigInteger.valueOf(3)).add(a);
                BigInteger denominator = p1.y.multiply(BigInteger.valueOf(2));
                lambda = numerator.multiply(denominator.modInverse(p)).mod(p);
            } else {
                return new ECPoint(null, null); // 无穷远点
            }
        } else {
            // 点加法
            BigInteger numerator = p2.y.subtract(p1.y);
            BigInteger denominator = p2.x.subtract(p1.x);
            lambda = numerator.multiply(denominator.modInverse(p)).mod(p);
        }

        BigInteger x3 = lambda.pow(2).subtract(p1.x).subtract(p2.x).mod(p);
        BigInteger y3 = lambda.multiply(p1.x.subtract(x3)).subtract(p1.y).mod(p);
        return new ECPoint(x3, y3);
    }

    /**
     * 标量乘法（快速幂算法）
     */
    public static ECPoint scalarMultiply(BigInteger k, ECPoint point) {
        ECPoint result = new ECPoint(null, null);
        ECPoint current = point;

        for (int i = 0; i < k.bitLength(); i++) {
            if (k.testBit(i)) {
                result = pointAdd(result, current);
            }
            current = pointAdd(current, current);
        }

        return result;
    }

    /**
     * 生成密钥对
     */
    public static KeyPair generateKeyPair() {
        SecureRandom random = new SecureRandom();
        BigInteger privateKey;
        ECPoint publicKeyPoint;

        do {
            // 生成合法私钥 (1 <= privateKey < n)
            do {
                privateKey = new BigInteger(n.bitLength(), random);
            } while (privateKey.compareTo(BigInteger.ONE) < 0 || privateKey.compareTo(n) >= 0);
            // 计算公钥点
            publicKeyPoint = scalarMultiply(privateKey, G);
        } while (!isPointOnCurve(publicKeyPoint)); // 确保公钥在曲线上

        byte[] publicKey = publicKeyPoint.x.toByteArray();
        return new KeyPair(publicKey, privateKey.toByteArray());
    }

    /**
     * 加密函数
     */
    public static Ciphertext encrypt(byte[] publicKey, byte[] plaintext) {
        try {
            // 1. 重建公钥点
            BigInteger pubX = new BigInteger(1, publicKey);
            ECPoint publicKeyPoint = reconstructPoint(pubX);
            // 2. 生成临时密钥对
            KeyPair ephemeral = generateKeyPair();
            BigInteger ephemeralPrivate = new BigInteger(1, ephemeral.privateKey);
            // 3. 计算共享密钥
            ECPoint sharedPoint = scalarMultiply(ephemeralPrivate, publicKeyPoint);
            byte[] sharedSecret = sha256(sharedPoint.x.toByteArray());
            // 4. 加密数据
            byte[] encrypted = xorEncrypt(plaintext, sharedSecret);
            return new Ciphertext(ephemeral.publicKey, encrypted);
        } catch (Exception e) {
            throw new RuntimeException("加密失败", e);
        }
    }

    /**
     * 解密函数
     */
    public static byte[] decrypt(byte[] privateKey, Ciphertext ciphertext) {
        try {
            // 1. 重建临时公钥点
            BigInteger ephemeralX = new BigInteger(1, ciphertext.ephemeralPubKey);
            ECPoint ephemeralPoint = reconstructPoint(ephemeralX);
            // 2. 计算共享密钥
            BigInteger priv = new BigInteger(1, privateKey);
            ECPoint sharedPoint = scalarMultiply(priv, ephemeralPoint);
            byte[] sharedSecret = sha256(sharedPoint.x.toByteArray());
            // 3. 解密数据
            return xorEncrypt(ciphertext.encryptedData, sharedSecret);
        } catch (Exception e) {
            throw new RuntimeException("解密失败", e);
        }
    }

    // ------------------------ 辅助函数 ------------------------

    private static ECPoint reconstructPoint(BigInteger x) {
        BigInteger rhs = x.pow(3).add(a.multiply(x)).add(b).mod(p);
        BigInteger y = sqrt(rhs, p);
        return new ECPoint(x, y);
    }

    private static byte[] xorEncrypt(byte[] data, byte[] key) {
        byte[] result = new byte[data.length];
        for (int i = 0; i < data.length; i++) {
            result[i] = (byte) (data[i] ^ key[i % key.length]);
        }
        return result;
    }

    private static byte[] sha256(byte[] input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(input);
        } catch (Exception e) {
            throw new RuntimeException("SHA-256不可用", e);
        }
    }

    /**
     * Tonelli-Shanks 算法计算模平方根
     * 解决方程 x² ≡ a (mod p)，其中 p 是奇素数
     *
     * @param a 要求平方根的数
     * @param p 模数（必须是奇素数）
     * @return 满足 x² ≡ a (mod p) 的 x 值
     * @throws IllegalArgumentException 如果 a 不是模 p 的二次剩余或 p 不是奇素数
     */
    private static BigInteger sqrt(BigInteger a, BigInteger p) {
        // 1. 处理特殊情况
        if (a.equals(BigInteger.ZERO)) {
            return BigInteger.ZERO;
        }
        if (p.equals(BigInteger.valueOf(2))) {
            return a; // 对于 p=2，任何数都是自身的平方根
        }

        // 2. 检查是否为二次剩余 (欧拉准则)
        if (!a.modPow(p.subtract(BigInteger.ONE).divide(BigInteger.valueOf(2)), p).equals(BigInteger.ONE)) {
            throw new IllegalArgumentException("无平方根：" + a.toString(16) + " 不是模 " + p.toString(16) + " 的二次剩余");
        }

        // 3. 特殊情况：p ≡ 3 mod 4 (简单情况)
        if (p.mod(BigInteger.valueOf(4)).equals(BigInteger.valueOf(3))) {
            return a.modPow(p.add(BigInteger.ONE).divide(BigInteger.valueOf(4)), p);
        }

        // 4. 一般情况 (Tonelli-Shanks 算法)

        // 步骤1：分解 p-1 = Q * 2^S
        BigInteger q = p.subtract(BigInteger.ONE);
        int s = 0;
        while (q.mod(BigInteger.valueOf(2)).equals(BigInteger.ZERO)) {
            q = q.divide(BigInteger.valueOf(2));
            s++;
        }

        // 步骤2：寻找二次非剩余 z
        BigInteger z = BigInteger.valueOf(2);
        while (z.modPow(p.subtract(BigInteger.ONE).divide(BigInteger.valueOf(2)), p).equals(BigInteger.ONE)) {
            z = z.add(BigInteger.ONE);
        }
        BigInteger c = z.modPow(q, p);

        // 步骤3：初始化变量
        BigInteger x = a.modPow(q.add(BigInteger.ONE).divide(BigInteger.valueOf(2)), p);
        BigInteger t = a.modPow(q, p);
        int m = s;

        // 步骤4：循环直到找到平方根
        while (!t.equals(BigInteger.ONE)) {
            // 找到最小的 i 使得 t^(2^i) ≡ 1 mod p
            int i = 0;
            BigInteger temp = t;
            while (!temp.equals(BigInteger.ONE)) {
                temp = temp.modPow(BigInteger.valueOf(2), p);
                i++;
                if (i >= m) {
                    throw new RuntimeException("算法失败：无法找到平方根");
                }
            }

            // 更新变量
            BigInteger b = c.modPow(BigInteger.valueOf(2).pow(m - i - 1), p);
            x = x.multiply(b).mod(p);
            t = t.multiply(b).mod(p).multiply(b).mod(p);
            c = b.modPow(BigInteger.valueOf(2), p);
            m = i;
        }

        return x;
    }

    private static boolean isPointOnCurve(ECPoint point) {
        if (point.isInfinity()) return true;
        BigInteger lhs = point.y.pow(2).mod(p);
        BigInteger rhs = point.x.pow(3)
                .add(a.multiply(point.x))
                .add(b)
                .mod(p);
        return lhs.equals(rhs);
    }
    // ------------------------ 测试用例 ------------------------

    public static void main(String[] args) {
        System.out.println("=== ECC160算法测试 ===");

        // 测试1: 验证曲线参数
        testCurveParameters();

        // 测试2: 加解密流程
        testEncryptionDecryption();

        // 测试3: 边界测试
        testEdgeCases();
    }

    private static void testCurveParameters() {
        System.out.println("\n[测试1] 验证曲线参数:");
        System.out.println("生成点G是否在曲线上: " + isPointOnCurve(G));

        ECPoint testPoint = scalarMultiply(BigInteger.valueOf(123456), G);
        System.out.println("随机点校验: " + isPointOnCurve(testPoint));
    }

    private static void testEncryptionDecryption() {
        System.out.println("\n[测试2] 加解密测试:");

        // 生成密钥对
        KeyPair keyPair = generateKeyPair();
        System.out.println("私钥长度: " + keyPair.privateKey.length + " bytes");
        System.out.println("公钥长度: " + keyPair.publicKey.length + " bytes");

        // 加密测试
        String originalText = "lzyHello, ECC160! 测试消息 2023";
        Ciphertext ciphertext = encrypt(keyPair.publicKey, originalText.getBytes());
        System.out.println("加密后长度: " + ciphertext.encryptedData.length + " bytes");

        // 解密测试
        byte[] decrypted = decrypt(keyPair.privateKey, ciphertext);
        String decryptedText = new String(decrypted);
        System.out.println("解密结果: " + decryptedText);
        System.out.println("验证结果: " + originalText.equals(decryptedText));
    }

    private static void testEdgeCases() {
        System.out.println("\n[测试3] 边界测试:");

        // 空消息测试
        KeyPair kp = generateKeyPair();
        Ciphertext ct = encrypt(kp.publicKey, new byte[0]);
        byte[] pt = decrypt(kp.privateKey, ct);
        System.out.println("空消息测试: " + (pt.length == 0));

        // 大消息测试 (1KB)
        byte[] bigData = new byte[1024];
        new SecureRandom().nextBytes(bigData);
        ct = encrypt(kp.publicKey, bigData);
        pt = decrypt(kp.privateKey, ct);
        System.out.println("大消息测试: " + Arrays.equals(bigData, pt));
    }


}

