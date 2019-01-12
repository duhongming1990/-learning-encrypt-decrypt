package com.zgl.util.secure.enums;

/**
 * @Author duhongming
 * @Email 19919902414@189.cn
 * @Date 2018/8/16 9:26
 */
public enum EnumAuthCodeAlgorithm {
    //BC实现 128
    HmacMD2("HmacMD2"),
    //BC实现 128
    HmacMD4("HmacMD4"),
    //JDK实现 128
    HmacMD5("HmacMD5"),

    //JDK实现 160
    HmacSHA1("HmacSHA-1"),
    //BC实现
    HmacSHA224("HmacSHA-224"),
    //JDK实现
    HmacSHA256("HmacSHA-256"),
    //JDK实现
    HmacSHA384("HmacSHA-384"),
    //JDK实现
    HmacSHA512("HmacSHA-512");

    private String value;
    public String getValue() {
        return value;
    }

    EnumAuthCodeAlgorithm(String value){
        this.value = value;
    }

}