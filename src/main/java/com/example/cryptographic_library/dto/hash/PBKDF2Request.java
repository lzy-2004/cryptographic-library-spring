package com.example.cryptographic_library.dto.hash;

/**
 * PBKDF2请求参数传输对象
 *
 * <p>包含：
 * <ul>
 *   <li>password: 原始密码（建议8字符以上）</li>
 *   <li>salt: 盐值字符串（推荐使用随机生成）</li>
 *   <li>iterations: 迭代次数（需≥1000）</li>
 *   <li>keyLength: 派生密钥字节长度（16-1024）</li>
 *   <li>outputEncoding: 输出编码格式</li>
 * </ul>
 */
public class PBKDF2Request {
    private String password;    // 密码字符串
    private String salt;        // Base64或Hex编码的盐值
    private int iterations;     // 迭代次数
    private int keyLength;      // 派生密钥字节长度
    private String outputEncoding; // 输出编码（base64/hex)

    public PBKDF2Request(String password, String salt, String saltEncoding, int iterations, int keyLength, String outputEncoding) {
        this.password = password;
        this.salt = salt;
        this.iterations = iterations;
        this.keyLength = keyLength;
        this.outputEncoding = outputEncoding;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getSalt() {
        return salt;
    }

    public void setSalt(String salt) {
        this.salt = salt;
    }

    public int getIterations() {
        return iterations;
    }

    public void setIterations(int iterations) {
        this.iterations = iterations;
    }

    public int getKeyLength() {
        return keyLength;
    }

    public void setKeyLength(int keyLength) {
        this.keyLength = keyLength;
    }

    public String getOutputEncoding() {
        return outputEncoding;
    }

    public void setOutputEncoding(String outputEncoding) {
        this.outputEncoding = outputEncoding;
    }
}
