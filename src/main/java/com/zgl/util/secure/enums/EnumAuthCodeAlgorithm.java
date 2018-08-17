package com.zgl.util.secure.enums;

/**
 * @Author duhongming
 * @Email 19919902414@189.cn
 * @Date 2018/8/16 9:26
 */
public enum EnumAuthCodeAlgorithm {

    HmacMD5("HmacMD5"),

    HmacSHA1("HmacSHA-1"),
    HmacSHA224("HmacSHA-224"),
    HmacSHA256("HmacSHA-256"),
    HmacSHA384("HmacSHA-384"),
    HmacSHA512("HmacSHA-512");

    private String value;
    public String getValue() {
        return value;
    }

    EnumAuthCodeAlgorithm(String value){
        this.value = value;
    }

}