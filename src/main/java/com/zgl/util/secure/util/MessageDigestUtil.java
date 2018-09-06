package com.zgl.util.secure.util;

import com.zgl.util.NumberUtil;
import com.zgl.util.secure.enums.EnumDigestAlgorithm;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.Validate;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.*;


/**
 * 消息摘要工具类
 * @author ZGL
 *
 */
@Slf4j
public class MessageDigestUtil {

	private static SecureRandom random = new SecureRandom();

	public static byte[] encode(EnumDigestAlgorithm digestAlgorithm, byte[] byteData) throws NoSuchAlgorithmException{
		Security.addProvider(new BouncyCastleProvider());
		return MessageDigest.getInstance(digestAlgorithm.name()).digest(byteData);
	}

	public static byte[] encodeWithSalt(EnumDigestAlgorithm digestAlgorithm, byte[] byteData, byte[] salt) throws NoSuchAlgorithmException{
		Security.addProvider(new BouncyCastleProvider());
		return MessageDigest.getInstance(digestAlgorithm.name()).digest(byteData);
	}

//	public static byte[] encodeWithSaltIterations(EnumDigestAlgorithm digestAlgorithm, byte[] byteData, byte[] salt, int iterations){
//		try{
//			Security.addProvider(new BouncyCastleProvider());
//			MessageDigest digest = MessageDigest.getInstance(digestAlgorithm.name());
//			if (salt != null) {
//				digest.update(salt);
//			}
//
//			byte[] result = digest.digest(byteData);
//
//			for (int i = 1; i < iterations; i++) {
//				digest.reset();
//				result = digest.digest(result);
//			}
//			return result;
//		} catch (GeneralSecurityException e) {
//			throw Exceptions.unchecked(e);
//		}
//	}

	/**
	 * 生成随机的Byte[]作为salt.
	 *
	 * @param numBytes byte数组的大小
	 */
	public static byte[] generateSalt(int numBytes) {
		Validate.isTrue(numBytes > 0, "numBytes argument must be a positive integer (1 or larger)", numBytes);

		byte[] bytes = new byte[numBytes];
		random.nextBytes(bytes);
		return bytes;
	}

	public static void main(String[] args) throws NoSuchAlgorithmException, IOException {
		String dataString = "ZGL";
		/**
		 *
		 * MD是消息摘要（Message Digest），它们都不安全了。
		 * SHA-1已经不安全了，SHA-2还尚未被攻破。
		 */
		for (EnumDigestAlgorithm digestAlgorithm : EnumDigestAlgorithm.values()) {
			byte[] md = encode(digestAlgorithm, dataString.getBytes());
			log.info("{},文本摘要信息: {}", digestAlgorithm.getValue(), NumberUtil.bytesToStrHex(md));
		}


		log.info("前后台通用MD5摘要信息: {}",NumberUtil.bytesToStrHex(encode(EnumDigestAlgorithm.MD5, "消息摘要".getBytes())));
		log.info("前后台通用SHA256摘要信息: {}",NumberUtil.bytesToStrHex(encode(EnumDigestAlgorithm.SHA256, "消息摘要".getBytes())));

		byte[] bytes = new MessageDigestUtil().inputStream2ByteArray("E:\\personal-software-auto\\Hadoop\\1.Hadoop\\hadoop-3.1.1.tar.gz");
		//文件指纹，参见文件hadoop-3.1.1.tar.gz.mds.txt
		for (EnumDigestAlgorithm digestAlgorithm : EnumDigestAlgorithm.values()) {
			byte[] md = encode(digestAlgorithm,bytes);
			log.info("{},文件摘要信息: {}", digestAlgorithm.getValue(),NumberUtil.bytesToStrHex(md));
		}

	}

	private byte[] inputStream2ByteArray(String filePath) throws IOException {

		InputStream in = new FileInputStream(filePath);
		byte[] data = toByteArray(in);
		in.close();

		return data;
	}

	private byte[] toByteArray(InputStream in) throws IOException {

		ByteArrayOutputStream out = new ByteArrayOutputStream();
		byte[] buffer = new byte[1024 * 4];
		int n = 0;
		while ((n = in.read(buffer)) != -1) {
			out.write(buffer, 0, n);
		}
		return out.toByteArray();
	}
}