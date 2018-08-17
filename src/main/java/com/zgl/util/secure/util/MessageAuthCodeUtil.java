package com.zgl.util.secure.util;

import com.zgl.util.NumberUtil;
import com.zgl.util.secure.enums.EnumAuthCodeAlgorithm;
import lombok.extern.slf4j.Slf4j;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * @Author duhongming
 * @Email 19919902414@189.cn
 * @Date 2018/8/16 9:30
 */
@Slf4j
public class MessageAuthCodeUtil {

    public static byte[] encode(EnumAuthCodeAlgorithm authCodeAlgorithm, byte[] byteData, byte[] keyData) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac mac = Mac.getInstance(authCodeAlgorithm.name());
        SecretKey secretKey = new SecretKeySpec(keyData, authCodeAlgorithm.name());
        mac.init(secretKey);
        return mac.doFinal(byteData);
    }

    public static void main(String[] args) throws InvalidKeyException, NoSuchAlgorithmException {

        String dataString = "ZGL";

        for (EnumAuthCodeAlgorithm authCodeAlgorithm : EnumAuthCodeAlgorithm.values()){
            log.info(authCodeAlgorithm.getValue());
            SecretKey secretKey = KeyUtil.generateKey(authCodeAlgorithm);
            log.info("消息验证码的密钥： {}", NumberUtil.bytesToStrHex(secretKey.getEncoded()));
            byte[] mac = encode(authCodeAlgorithm,dataString.getBytes(),secretKey.getEncoded());
            log.info("消息验证码后数据: {}", NumberUtil.bytesToStrHex(mac));
        }

        log.info("前后台通用HmacMD5消息验证码: {}",NumberUtil.bytesToStrHex(encode(EnumAuthCodeAlgorithm.HmacMD5, "消息摘要".getBytes(),"HmacMD5".getBytes())));
        log.info("前后台通用HmacSHA256消息验证码: {}",NumberUtil.bytesToStrHex(encode(EnumAuthCodeAlgorithm.HmacSHA256, "消息摘要".getBytes(),"HmacSHA256".getBytes())));
    }
}