package com.example.cryptographic_library.dto.asymmetric;


public class ECC160DTO {
    /**
     * ECC160密钥对响应对象
     *
     * <p>字段说明：
     * <ul>
     *   <li>publicKey: Base64编码压缩公钥（20字节）</li>
     *   <li>privateKey: Base64编码私钥（21字节）</li>
     * </ul>
     */
    public static class KeyPairResponse {
        private String publicKey;  // Base64
        private String privateKey; // Base64

        public KeyPairResponse(String publicKey, String privateKey) {
            this.publicKey = publicKey;
            this.privateKey = privateKey;
        }

        public String getPublicKey() {
            return publicKey;
        }

        public void setPublicKey(String publicKey) {
            this.publicKey = publicKey;
        }

        public String getPrivateKey() {
            return privateKey;
        }

        public void setPrivateKey(String privateKey) {
            this.privateKey = privateKey;
        }
    }

    /**
     * ECC160加密请求参数
     *
     * <p>要求：
     * <ul>
     *   <li>publicKey: 有效ECC160公钥（Base64编码）</li>
     *   <li>plaintext: 任意字符串格式明文（最大256KB）</li>
     *   <li>isBase64: 明文是否已经是Base64编码（默认false）</li>
     * </ul>
     */
    public static class EncryptRequest {
        private String publicKey;  // Base64
        private String plaintext; // 普通字符串或Base64
        private boolean isBase64; // 标识明文是否已经是Base64编码

        public EncryptRequest() {
            // 默认构造函数
        }

        public EncryptRequest(String publicKey, String plaintext) {
            this.publicKey = publicKey;
            this.plaintext = plaintext;
            this.isBase64 = false; // 默认为普通字符串
        }

        public EncryptRequest(String publicKey, String plaintext, boolean isBase64) {
            this.publicKey = publicKey;
            this.plaintext = plaintext;
            this.isBase64 = isBase64;
        }

        public String getPublicKey() {
            return publicKey;
        }

        public void setPublicKey(String publicKey) {
            this.publicKey = publicKey;
        }

        public String getPlaintext() {
            return plaintext;
        }

        public void setPlaintext(String plaintext) {
            this.plaintext = plaintext;
        }

        public boolean isBase64() {
            return isBase64;
        }

        public void setBase64(boolean base64) {
            isBase64 = base64;
        }
    }
    /**
     * ECC160解密请求参数
     *
     * <p>要求：
     * <ul>
     *   <li>privateKey: 与加密公钥配对的私钥</li>
     *   <li>ciphertext: 由本系统生成的加密数据</li>
     * </ul>
     */

    public static class DecryptRequest {
        private String privateKey; // Base64
        private String ciphertext; // Base64

        public DecryptRequest(String privateKey, String ciphertext) {
            this.privateKey = privateKey;
            this.ciphertext = ciphertext;
        }

        public String getPrivateKey() {
            return privateKey;
        }

        public void setPrivateKey(String privateKey) {
            this.privateKey = privateKey;
        }

        public String getCiphertext() {
            return ciphertext;
        }

        public void setCiphertext(String ciphertext) {
            this.ciphertext = ciphertext;
        }
    }

    /**
     * 加密/解密响应通用对象
     *
     * <p>data字段说明：
     * <ul>
     *   <li>加密时：Base64(临时公钥20B || 密文)</li>
     *   <li>解密时：原始明文字符串</li>
     *   <li>isBase64: 标识结果是否是Base64编码（解密时有效）</li>
     * </ul>
     */
    public static class CryptoResponse {
        private String data; // Base64或原始字符串
        private boolean isBase64; // 标识数据是否是Base64编码

        public CryptoResponse(String data) {
            this.data = data;
            this.isBase64 = true; // 默认为Base64
        }

        public CryptoResponse(String data, boolean isBase64) {
            this.data = data;
            this.isBase64 = isBase64;
        }

        public String getData() {
            return data;
        }

        public void setData(String data) {
            this.data = data;
        }

        public boolean isBase64() {
            return isBase64;
        }

        public void setBase64(boolean base64) {
            isBase64 = base64;
        }
    }
}
