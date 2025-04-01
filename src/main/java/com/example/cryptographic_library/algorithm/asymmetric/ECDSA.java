package com.example.cryptographic_library.algorithm.asymmetric;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

public class ECDSA {
    // 椭圆曲线参数（SECP160R1）
    private static final BigInteger p = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFF", 16);
    private static final BigInteger a = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFC", 16);
    private static final BigInteger b = new BigInteger("1C97BEFC54BD7A8B65ACF89F81D4D4ADC565FA45", 16);
    private static final BigInteger n = new BigInteger("0100000000000000000001F4C8F927AED3CA752257", 16);
    private static final ECPoint G = new ECPoint(
            new BigInteger("4A96B5688EF573284664698968C38BB913CBFC82", 16),
            new BigInteger("23A628553168947D59DCC912042351377AC5FB32", 16)
    );

    // 椭圆曲线点类
    private static class ECPoint {
        final BigInteger x;
        final BigInteger y;

        ECPoint(BigInteger x, BigInteger y) {
            if (x != null && y != null && !isOnCurve(x, y)) {
                throw new IllegalArgumentException("Point not on curve");
            }
            this.x = x;
            this.y = y;
        }

        boolean isInfinity() {
            return x == null && y == null;
        }
    }

    // 密钥对类（包含完整坐标）
    public static class KeyPair {
        public final byte[] publicKeyX;
        public final byte[] publicKeyY;
        public final byte[] privateKey;

        public KeyPair(byte[] publicKeyX, byte[] publicKeyY, byte[] privateKey) {
            this.publicKeyX = publicKeyX;
            this.publicKeyY = publicKeyY;
            this.privateKey = privateKey;
        }
    }

    // 签名类
    public static class Signature {
        public final byte[] r;
        public final byte[] s;

        public Signature(byte[] r, byte[] s) {
            this.r = r;
            this.s = s;
        }
    }

    //============== 核心算法实现 ==============//

    // 生成密钥对
    public static KeyPair generateKeyPair() {
        SecureRandom random = new SecureRandom();
        BigInteger privateKey;
        do {
            privateKey = new BigInteger(n.bitLength(), random);
        } while (privateKey.compareTo(n) >= 0 || privateKey.signum() <= 0);

        ECPoint publicKeyPoint = scalarMultiply(privateKey, G);
        return new KeyPair(
                stripLeadingZeros(publicKeyPoint.x.toByteArray()),
                stripLeadingZeros(publicKeyPoint.y.toByteArray()),
                stripLeadingZeros(privateKey.toByteArray())
        );
    }

    // 签名生成
    public static Signature sign(byte[] privateKey, byte[] message) {
        BigInteger d = new BigInteger(1, privateKey);
        BigInteger e = new BigInteger(1, sha256(message)).mod(n);

        BigInteger r, s;
        do {
            BigInteger k = generateRandomK();
            ECPoint kG = scalarMultiply(k, G);
            r = kG.x.mod(n);
            s = k.modInverse(n).multiply(e.add(d.multiply(r))).mod(n);
        } while (r.signum() == 0 || s.signum() == 0);

        return new Signature(
                stripLeadingZeros(r.toByteArray()),
                stripLeadingZeros(s.toByteArray())
        );
    }

    // 签名验证
    public static boolean verify(KeyPair keyPair, byte[] message, Signature sig) {
        try {
            // 1. 参数校验
            BigInteger r = new BigInteger(1, sig.r);
            BigInteger s = new BigInteger(1, sig.s);
            if (!validateSignatureRange(r, s)) return false;

            // 2. 重建公钥点
            ECPoint publicKeyPoint = new ECPoint(
                    new BigInteger(1, keyPair.publicKeyX),
                    new BigInteger(1, keyPair.publicKeyY)
            );

            // 3. 计算中间值
            BigInteger e = new BigInteger(1, sha256(message)).mod(n);
            BigInteger w = s.modInverse(n);
            BigInteger u1 = e.multiply(w).mod(n);
            BigInteger u2 = r.multiply(w).mod(n);

            // 4. 点运算
            ECPoint point = addPoints(
                    scalarMultiply(u1, G),
                    scalarMultiply(u2, publicKeyPoint)
            );

            return r.equals(point.x.mod(n));
        } catch (Exception ex) {
            return false;
        }
    }

    //============== 辅助方法 ==============//

    // 点加法
    private static ECPoint addPoints(ECPoint p1, ECPoint p2) {
        if (p1.isInfinity()) return p2;
        if (p2.isInfinity()) return p1;
        validatePoint(p1);
        validatePoint(p2);

        BigInteger lambda;
        if (p1.x.equals(p2.x)) {
            if (p1.y.equals(p2.y)) {
                // 点加倍
                BigInteger numerator = p1.x.pow(2).multiply(BigInteger.valueOf(3)).add(a);
                BigInteger denominator = p1.y.multiply(BigInteger.valueOf(2));
                lambda = numerator.multiply(denominator.modInverse(p)).mod(p);
            } else {
                return new ECPoint(null, null); // 无穷远点
            }
        } else {
            // 常规点加法
            BigInteger numerator = p2.y.subtract(p1.y);
            BigInteger denominator = p2.x.subtract(p1.x);
            lambda = numerator.multiply(denominator.modInverse(p)).mod(p);
        }

        BigInteger x3 = lambda.pow(2).subtract(p1.x).subtract(p2.x).mod(p);
        BigInteger y3 = lambda.multiply(p1.x.subtract(x3)).subtract(p1.y).mod(p);
        return new ECPoint(x3, y3);
    }

    // 标量乘法
    private static ECPoint scalarMultiply(BigInteger k, ECPoint point) {
        validatePoint(point);
        ECPoint result = new ECPoint(null, null);
        ECPoint current = point;
        while (k.signum() > 0) {
            if (k.testBit(0)) {
                result = addPoints(result, current);
            }
            current = addPoints(current, current);
            k = k.shiftRight(1);
        }
        return result;
    }

    //============== 工具方法 ==============//

    private static boolean isOnCurve(BigInteger x, BigInteger y) {
        BigInteger lhs = y.modPow(BigInteger.TWO, p);
        BigInteger rhs = x.modPow(BigInteger.valueOf(3), p)
                .add(a.multiply(x).mod(p))
                .add(b).mod(p);
        return lhs.equals(rhs);
    }

    private static void validatePoint(ECPoint point) {
        if (!point.isInfinity() && !isOnCurve(point.x, point.y)) {
            throw new IllegalArgumentException("Invalid curve point");
        }
    }

    private static boolean validateSignatureRange(BigInteger r, BigInteger s) {
        return r.compareTo(BigInteger.ONE) >= 0 && r.compareTo(n) < 0 &&
                s.compareTo(BigInteger.ONE) >= 0 && s.compareTo(n) < 0;
    }

    private static BigInteger generateRandomK() {
        byte[] randomBytes = new byte[20]; // 160位
        new SecureRandom().nextBytes(randomBytes);
        return new BigInteger(1, randomBytes).mod(n);
    }

    private static byte[] stripLeadingZeros(byte[] bytes) {
        int startIndex = 0;
        while (startIndex < bytes.length && bytes[startIndex] == 0) {
            startIndex++;
        }
        return Arrays.copyOfRange(bytes, startIndex, bytes.length);
    }

    private static byte[] sha256(byte[] input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(input);
        } catch (Exception e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    //============== 测试用例 ==============//

    public static void main(String[] args) {
        // 生成密钥对
        KeyPair keyPair = generateKeyPair();
        System.out.println("Private Key: " + new BigInteger(1, keyPair.privateKey).toString(16));
        System.out.println("Public Key X: " + new BigInteger(1, keyPair.publicKeyX).toString(16));
        System.out.println("Public Key Y: " + new BigInteger(1, keyPair.publicKeyY).toString(16));

        // 签名验证测试
        String message = "Hello ECDSA!";
        byte[] msgBytes = message.getBytes();
        Signature signature = sign(keyPair.privateKey, msgBytes);
        System.out.println("\nSignature R: " + new BigInteger(1, signature.r).toString(16));
        System.out.println("Signature S: " + new BigInteger(1, signature.s).toString(16));

        boolean isValid = verify(keyPair, msgBytes, signature);
        System.out.println("\nVerification Result: " + isValid);
        SecureRandom random = new SecureRandom();
        byte[] randomR = new byte[20];
        byte[] randomS = new byte[20];
        random.nextBytes(randomR);
        random.nextBytes(randomS);
        Signature fakeSignature2 = new Signature(randomR, randomS);
        boolean isValid1 = verify(keyPair, msgBytes, fakeSignature2);
        System.out.println("\nVerification Result1: " + isValid1);
    }
}
