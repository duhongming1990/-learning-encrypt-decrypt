package com.zgl.util.secure.util;

import com.zgl.util.EncodingUtil;
import org.bouncycastle.util.encoders.Base64;
import sun.misc.BASE64Decoder;

import java.io.IOException;
import java.io.UnsupportedEncodingException;

public class Base64Util {
	public static byte[] encode(byte[] byteData){
		return  Base64.encode(byteData);
	}
	
	public static byte[] decode(byte[] byteData){
		return  Base64.decode(byteData);
	}
	
	public static String encode(String data) throws UnsupportedEncodingException{
		return new String(encode(data.getBytes()));
	}
	
	public static String decode(String data) throws UnsupportedEncodingException{
		return new String(decode(data.getBytes()));
	}
	
	public static byte[] encode2Bytes(String data) throws UnsupportedEncodingException{
		return encode(data.getBytes());
	}
	
	public static byte[] decode2Bytes(String data) throws UnsupportedEncodingException{
		return decode(data.getBytes());
	}
	
	public static String encode2Str(byte[] byteData) throws UnsupportedEncodingException{
		return  new String(encode(byteData));
	}
	
	public static String decode2Str(byte[] byteData) throws UnsupportedEncodingException{
		return new String(decode(byteData));
	}
	
	
	
	public static String encode(String data,String encoding) throws UnsupportedEncodingException{
		return new String(encode(data.getBytes(encoding)), EncodingUtil.getEncoding(encoding));
	}
	
	public static String decode(String data,String encoding) throws UnsupportedEncodingException{
		return new String(decode(data.getBytes(encoding)),EncodingUtil.getEncoding(encoding));
	}
	
	public static byte[] encode2Bytes(String data,String encoding) throws UnsupportedEncodingException{
		return encode(data.getBytes(EncodingUtil.getEncoding(encoding)));
	}
	
	public static byte[] decode2Bytes(String data,String encoding) throws UnsupportedEncodingException{
		return decode(data.getBytes(EncodingUtil.getEncoding(encoding)));
	}
	
	public static String encode2Str(byte[] byteData, String encoding) throws UnsupportedEncodingException{
		return  new String(encode(byteData),EncodingUtil.getEncoding(encoding));
	}
	
	public static String decode2Str(byte[] byteData,String encoding) throws UnsupportedEncodingException{
		return new String(decode(byteData),EncodingUtil.getEncoding(encoding));
	}
	
	
	public static void main(String[] args) throws Exception {
		String dataString = "ZGL";
		System.out.println("Base64编码前数据：" + dataString);
		String e = encode(dataString, "utf-8");
		System.out.println("Base64编码后数据：" + e);
		System.out.println("Base64解码后数据：" + decode(e, "utf-8"));

//		String base64Result = "MDEyMzQ1Njc4Oe+8jDAxMjM0NTY3ODnvvIwwMTIzNDU2Nzg577yMMDEyMzQ1Njc4Oe+8jDAxMjM0" +
//				"NTY3ODnvvIwwMTIzNDU2Nzg577yMMDEyMzQ1Njc4OQ==";
//		byte[] ss = java.util.Base64.getDecoder().decode(base64Result);
//		System.out.println("ss = " + new String(ss));
//		String s = new String(new BASE64Decoder().decodeBuffer(base64Result));
//		System.out.println("s = " + s);
	}

}
