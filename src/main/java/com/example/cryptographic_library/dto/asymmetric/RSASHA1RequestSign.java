package com.example.cryptographic_library.dto.asymmetric;

public class RSASHA1RequestSign {

    String data;
    String privateKey;
    String modulus;

    /**
     * RSA-SHA1签名请求参数
     * @param data 原始待签名消息（明文UTF-8编码）
     * @param privateKey Base64编码的RSA私钥
     * @param modulus Base64编码的模数n
     */
    public RSASHA1RequestSign(String data, String privateKey, String modulus) {
        this.data = data;
        this.privateKey = privateKey;
        this.modulus = modulus;
    }

    public String getData() {
        return data;
    }

    public void setData(String data) {
        this.data = data;
    }

    public String getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(String privateKey) {
        this.privateKey = privateKey;
    }

    public String getModulus() {
        return modulus;
    }

    public void setModulus(String modulus) {
        this.modulus = modulus;
    }
}
