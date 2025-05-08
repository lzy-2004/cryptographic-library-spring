package com.example.cryptographic_library.service.encode;

import com.example.cryptographic_library.algorithm.encode.Hex;
import com.example.cryptographic_library.algorithm.encode.UTF_8;
import com.example.cryptographic_library.dto.encode.HexResponse;
import org.springframework.stereotype.Service;

@Service
public class HexService {
    public HexResponse encode(String data) {
        try {
            Hex hex = new Hex();
            String encoded = hex.encode(UTF_8.encode(data));
            return new HexResponse(0, "编码成功", encoded);
        } catch (Exception e) {
            return new HexResponse(-1, "编码失败: " + e.getMessage(), null);
        }
    }

    public HexResponse decode(String data) {
        try {
            Hex hex = new Hex();
            byte[] decoded = hex.decode(data);
            return new HexResponse(0, "解码成功", UTF_8.decode(decoded));
        } catch (Exception e) {
            return new HexResponse(-1, "解码失败: " + e.getMessage(), null);
        }
    }
}
