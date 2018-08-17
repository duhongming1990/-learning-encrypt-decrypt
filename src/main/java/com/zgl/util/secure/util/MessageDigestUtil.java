package com.zgl.util.secure.util;

import com.zgl.util.NumberUtil;
import com.zgl.util.secure.enums.EnumDigestAlgorithm;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

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
//
//	/**
//	 * 生成随机的Byte[]作为salt.
//	 *
//	 * @param numBytes byte数组的大小
//	 */
//	public static byte[] generateSalt(int numBytes) {
//		Validate.isTrue(numBytes > 0, "numBytes argument must be a positive integer (1 or larger)", numBytes);
//
//		byte[] bytes = new byte[numBytes];
//		random.nextBytes(bytes);
//		return bytes;
//	}

	public static void main(String[] args) throws NoSuchAlgorithmException {
		String dataString = "ZGL";
		/**
		 *
		 * MD是消息摘要（Message Digest），它们都不安全了。
		 * SHA-1已经不安全了，SHA-2还尚未被攻破。
		 */
		for (EnumDigestAlgorithm digestAlgorithm : EnumDigestAlgorithm.values()) {
			byte[] md = encode(digestAlgorithm, dataString.getBytes());
			log.info("{},摘要信息: {}", digestAlgorithm.getValue(), NumberUtil.bytesToStrHex(md));
		}


		log.info("前后台通用MD5摘要信息: {}",NumberUtil.bytesToStrHex(encode(EnumDigestAlgorithm.MD5, "消息摘要".getBytes())));
		log.info("前后台通用SHA256摘要信息: {}",NumberUtil.bytesToStrHex(encode(EnumDigestAlgorithm.SHA256, "消息摘要".getBytes())));
	
	}
}
