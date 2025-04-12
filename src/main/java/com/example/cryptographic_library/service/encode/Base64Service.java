package com.example.cryptographic_library.service.encode;

import com.example.cryptographic_library.algorithm.encode.Base64;
import com.example.cryptographic_library.algorithm.encode.UTF_8;
import com.example.cryptographic_library.dto.encode.Base64Response;
import org.springframework.stereotype.Service;

/**
 * Base64编解码服务实现类
 *
 * <p>处理业务逻辑，协调编码工具和字符集转换</p>
 */
@Service
public class Base64Service {
    /**
     * 执行Base64编码
     * @param data 待编码的原始字符串（UTF-8 格式）
     * @return 编码操作结果响应
     * @see Base64#encode(byte[])
     */
    public Base64Response encode(String data) {
        try {
            Base64 base64 = new Base64();
            String encrypted = base64.encode(UTF_8.encode(data));
            return new Base64Response(0, "编码成功", encrypted);
        } catch (Exception e) {
            return new Base64Response(-1, "编码失败: " + e.getMessage(), null);
        }
    }


    /**
     * 执行Base64解码
     * @param data 待解码的Base64字符串
     * @return 解码操作结果响应
     * @throws IllegalArgumentException 当输入包含非法字符或格式错误时抛出
     * @see Base64#decode(String)
     */
    public Base64Response decode(String data) {
        try {
            Base64 base64 = new Base64();
            byte[] decrypted = base64.decode(data);
            return new Base64Response(0, "解码成功", UTF_8.decode(decrypted));
        } catch (Exception e) {
            return new Base64Response(-1, "解码失败: " + e.getMessage(), null);
        }
    }
}
