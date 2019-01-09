package com.kd.op.util.sm;


import java.math.BigInteger;

public class Util 
{
	/**
	 * 整形转换成网络传输的字节流（字节数组）型数据
	 * 
	 * @param num 一个整型数据
	 * @return 4个字节的自己数组
	 */
	public static byte[] intToBytes(int num)
	{
		byte[] bytes = new byte[4];
		bytes[0] = (byte) (0xff & (num >> 0));
		bytes[1] = (byte) (0xff & (num >> 8));
		bytes[2] = (byte) (0xff & (num >> 16));
		bytes[3] = (byte) (0xff & (num >> 24));
		return bytes;
	}

	/**
	 * 四个字节的字节数据转换成一个整形数据
	 * 
	 * @param bytes 4个字节的字节数组
	 * @return 一个整型数据
	 */
	public static int byteToInt(byte[] bytes) 
	{
		int num = 0;
		int temp;
		temp = (0x000000ff & (bytes[0])) << 0;
		num = num | temp;
		temp = (0x000000ff & (bytes[1])) << 8;
		num = num | temp;
		temp = (0x000000ff & (bytes[2])) << 16;
		num = num | temp;
		temp = (0x000000ff & (bytes[3])) << 24;
		num = num | temp;
		return num;
	}

	/**
	 * 长整形转换成网络传输的字节流（字节数组）型数据
	 * 
	 * @param num 一个长整型数据
	 * @return 4个字节的自己数组
	 */
	public static byte[] longToBytes(long num) 
	{
		byte[] bytes = new byte[8];
		for (int i = 0; i < 8; i++) 
		{
			bytes[i] = (byte) (0xff & (num >> (i * 8)));
		}

		return bytes;
	}

	/**
	 * 大数字转换字节流（字节数组）型数据
	 * 
	 * @param n
	 * @return
	 */
	public static byte[] byteConvert32Bytes(BigInteger n) 
	{
		byte tmpd[] = (byte[])null;
        if(n == null)
        {
        	return null;
        }
        
        if(n.toByteArray().length == 33)
        {
            tmpd = new byte[32];
            System.arraycopy(n.toByteArray(), 1, tmpd, 0, 32);
        } 
        else if(n.toByteArray().length == 32)
        {
            tmpd = n.toByteArray();
        } 
        else
        {
            tmpd = new byte[32];
            for(int i = 0; i < 32 - n.toByteArray().length; i++)
            {
            	tmpd[i] = 0;
            }
            System.arraycopy(n.toByteArray(), 0, tmpd, 32 - n.toByteArray().length, n.toByteArray().length);
        }
        return tmpd;
	}
	
	/**
	 * 换字节流（字节数组）型数据转大数字
	 * 
	 * @param b
	 * @return
	 */
	public static BigInteger byteConvertInteger(byte[] b)
	{
	    if (b[0] < 0)
	    {
	    	byte[] temp = new byte[b.length + 1];
	    	temp[0] = 0;
	    	System.arraycopy(b, 0, temp, 1, b.length);
	    	return new BigInteger(temp);
	    }
	    return new BigInteger(b);
	}
	

    /**
     * 十六进制串转化为byte数组
     * 
     * @return the array of byte
     */
    public static byte[] hexToByte(String hex)
            throws IllegalArgumentException {
        if (hex.length() % 2 != 0) {
            throw new IllegalArgumentException();
        }
        char[] arr = hex.toCharArray();
        byte[] b = new byte[hex.length() / 2];
        for (int i = 0, j = 0, l = hex.length(); i < l; i++, j++) {
            String swap = "" + arr[i++] + arr[i];
            int byteint = Integer.parseInt(swap, 16) & 0xFF;
            b[j] = new Integer(byteint).byteValue();
        }
        return b;
    }
    
    /**
     * 字节数组转换为十六进制字符串
     * 
     * @param b
     *            byte[] 需要转换的字节数组
     * @return String 十六进制字符串
     */
    public static String byteToHex(byte b[]) {
        if (b == null) {
            throw new IllegalArgumentException(
                    "Argument b ( byte array ) is null! ");
        }
        StringBuffer hs = new StringBuffer();
        String stmp = "";
        for (int n = 0; n < b.length; n++) {
            stmp = Integer.toHexString(b[n] & 0xff);
            if (stmp.length() == 1) {
            	hs.append("0").append(stmp);
            } else {
            	hs.append(stmp);
            }
        }
        return hs.toString();
    }
    
}