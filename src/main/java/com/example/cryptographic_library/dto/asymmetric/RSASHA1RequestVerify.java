package com.example.cryptographic_library.dto.asymmetric;

public class RSASHA1RequestVerify {
    private String data;
    private String signature;
    private String publicKey;
    private String modulus;

    /**
     * @param data 原始消息（需与签名时完全一致）
     * @param signature Base64编码的签名数据
     * @param publicKey Base64编码的RSA公钥
     * @param modulus Base64编码的模数n
     */
    public RSASHA1RequestVerify(String data, String signature, String publicKey, String modulus) {
        this.data = data;
        this.signature = signature;
        this.publicKey = publicKey;
        this.modulus = modulus;
    }

    public String getData() {
        return data;
    }

    public void setData(String data) {
        this.data = data;
    }

    public String getSignature() {
        return signature;
    }

    public void setSignature(String signature) {
        this.signature = signature;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }

    public String getModulus() {
        return modulus;
    }

    public void setModulus(String modulus) {
        this.modulus = modulus;
    }
}
