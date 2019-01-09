package com.zgl.util.secure.util;

import java.util.zip.CRC32;

/**
 * @Author duhongming
 * @Email 19919902414@189.cn
 * @Date 2018/9/30 16:23
 *
 * 如果要求消息绝对不重复，
 * 推荐做法是对消息体使用 crc32 或
 * md5 来防止重复消息
 */
public class CRC32Util {

    public static long crc32Code(byte[] bytes) {
        CRC32 crc32 = new CRC32();
        crc32.update(bytes);
        return crc32.getValue();
    }

    public static void main(String[] args) {
        Long crc = CRC32Util.crc32Code("ZGL".getBytes());
        System.out.println("crc = " + crc);
    }
}