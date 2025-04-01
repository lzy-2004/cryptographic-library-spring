package com.example.cryptographic_library.dto.asymmetric;

public class ECDSADTO {

    public static class KeyPairResponse {
        private String publicKeyX;
        private String publicKeyY;
        private String privateKey;

        public KeyPairResponse(String publicKeyX, String publicKeyY, String privateKey) {
            this.publicKeyX = publicKeyX;
            this.publicKeyY = publicKeyY;
            this.privateKey = privateKey;
        }

        public String getPublicKeyX() {
            return publicKeyX;
        }

        public void setPublicKeyX(String publicKeyX) {
            this.publicKeyX = publicKeyX;
        }

        public String getPublicKeyY() {
            return publicKeyY;
        }

        public void setPublicKeyY(String publicKeyY) {
            this.publicKeyY = publicKeyY;
        }

        public String getPrivateKey() {
            return privateKey;
        }

        public void setPrivateKey(String privateKey) {
            this.privateKey = privateKey;
        }
    }


    public static class SignRequest {
        private String privateKey;
        private String message;

        public SignRequest(String privateKey, String message) {
            this.privateKey = privateKey;
            this.message = message;
        }

        public String getPrivateKey() {
            return privateKey;
        }

        public void setPrivateKey(String privateKey) {
            this.privateKey = privateKey;
        }

        public String getMessage() {
            return message;
        }

        public void setMessage(String message) {
            this.message = message;
        }
    }


    public static class SignResponse {
        private String r;
        private String s;

        public SignResponse(String r, String s) {
            this.r = r;
            this.s = s;
        }

        public String getR() {
            return r;
        }

        public void setR(String r) {
            this.r = r;
        }

        public String getS() {
            return s;
        }

        public void setS(String s) {
            this.s = s;
        }
    }


    public static class VerifyRequest {
        private String publicKeyX;
        private String publicKeyY;
        private String message;
        private String signatureR;
        private String signatureS;

        public VerifyRequest(String publicKeyX, String publicKeyY, String message, String signatureR, String signatureS) {
            this.publicKeyX = publicKeyX;
            this.publicKeyY = publicKeyY;
            this.message = message;
            this.signatureR = signatureR;
            this.signatureS = signatureS;
        }

        public String getPublicKeyX() {
            return publicKeyX;
        }

        public void setPublicKeyX(String publicKeyX) {
            this.publicKeyX = publicKeyX;
        }

        public String getPublicKeyY() {
            return publicKeyY;
        }

        public void setPublicKeyY(String publicKeyY) {
            this.publicKeyY = publicKeyY;
        }

        public String getMessage() {
            return message;
        }

        public void setMessage(String message) {
            this.message = message;
        }

        public String getSignatureR() {
            return signatureR;
        }

        public void setSignatureR(String signatureR) {
            this.signatureR = signatureR;
        }

        public String getSignatureS() {
            return signatureS;
        }

        public void setSignatureS(String signatureS) {
            this.signatureS = signatureS;
        }
    }


    public static class VerifyResponse {
        private boolean valid;
        private String message;

        public VerifyResponse(boolean valid, String message) {
            this.valid = valid;
            this.message = message;
        }

        public boolean isValid() {
            return valid;
        }

        public void setValid(boolean valid) {
            this.valid = valid;
        }

        public String getMessage() {
            return message;
        }

        public void setMessage(String message) {
            this.message = message;
        }
    }
}
