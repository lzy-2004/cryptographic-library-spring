package com.example.cryptographic_library.dto.encode;

public class Base64Request {
    private String data;

    public Base64Request(String data) {
        this.data = data;
    }

    public String getData() {
        return data;
    }

    public void setData(String data) {
        this.data = data;
    }
}
