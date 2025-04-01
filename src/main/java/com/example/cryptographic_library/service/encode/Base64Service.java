package com.example.cryptographic_library.service.encode;

import com.example.cryptographic_library.algorithm.encode.Base64;
import com.example.cryptographic_library.algorithm.encode.UTF_8;
import com.example.cryptographic_library.dto.encode.Base64Response;
import org.springframework.stereotype.Service;

@Service
public class Base64Service {
    public Base64Response encode(String data) {
        try {
            Base64 base64 = new Base64();
            String encrypted = base64.encode(UTF_8.encode(data)); // 修改点2

            return new Base64Response(0, "编码成功", encrypted);
        } catch (Exception e) {
            return new Base64Response(-1, "编码失败: " + e.getMessage(), null);
        }
    }

    public Base64Response decode(String data) {
        try {
            Base64 base64 = new Base64(); // 修改点3

            byte[] decrypted = base64.decode(data);

            return new Base64Response(0, "解码成功", UTF_8.decode(decrypted));
        } catch (Exception e) {
            return new Base64Response(-1, "解码失败: " + e.getMessage(), null);
        }
    }
}
