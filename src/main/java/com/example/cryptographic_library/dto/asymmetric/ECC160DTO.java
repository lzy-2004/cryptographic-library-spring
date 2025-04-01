package com.example.cryptographic_library.dto.asymmetric;


public class ECC160DTO {
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
