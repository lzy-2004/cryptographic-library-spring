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
     *   <li>publicKey: 有效ECC160公钥</li>
     *   <li>plaintext: Base64编码明文（最大256KB）</li>
     * </ul>
     */
    public static class EncryptRequest {
        private String publicKey;  // Base64
        private String plaintext; // Base64

        public EncryptRequest(String publicKey, String plaintext) {
            this.publicKey = publicKey;
            this.plaintext = plaintext;
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
     *   <li>解密时：Base64(原始明文)</li>
     * </ul>
     */
    public static class CryptoResponse {
        private String data; // Base64

        public CryptoResponse(String data) {
            this.data = data;
        }

        public String getData() {
            return data;
        }

        public void setData(String data) {
            this.data = data;
        }
    }
}
