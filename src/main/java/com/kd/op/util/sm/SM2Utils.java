package com.kd.op.util.sm;


import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement.Fp;
import org.bouncycastle.math.ec.ECPoint;

import java.io.IOException;
import java.math.BigInteger;

public class SM2Utils 
{
	private static final int c1XYL = 64;
	private static final int c3L = 64;
	
	/**
	 * <b>描述:生成随机密钥对</b> 
	 * @author zjc
	 * @return
	 */
	public static SM2Key getSm2Key(){
		SM2 sm2 = SM2.Instance();
		AsymmetricCipherKeyPair key = sm2.ecc_key_pair_generator.generateKeyPair();
		ECPrivateKeyParameters ecpriv = (ECPrivateKeyParameters) key.getPrivate();
		ECPublicKeyParameters ecpub = (ECPublicKeyParameters) key.getPublic();
		BigInteger privateKey = ecpriv.getD();
		ECPoint publicKey = ecpub.getQ();
		return new SM2Key(Util.byteToHex(publicKey.getEncoded()), Util.byteToHex(privateKey.toByteArray()));
	}
	
	/**
	 * <b>描述:数据加密</b> 
	 * @author zjc
	 * @return
	 * @throws IOException
	 */
	public static String encrypt(String publicKeyStr, String endata) throws IOException
	{
		if (publicKeyStr == null || publicKeyStr.length() == 0 ||
				endata == null || endata.length() == 0){
			return null;
		}
		byte[] publicKey = Util.hexToByte(publicKeyStr);
		byte[] data = endata.getBytes();
		StringBuffer sb = new StringBuffer(490);
		byte[] source = new byte[data.length];
		System.arraycopy(data, 0, source, 0, data.length);
		
		Cipher cipher = new Cipher();
		SM2 sm2 = SM2.Instance();
		ECPoint userKey = sm2.ecc_curve.decodePoint(publicKey);
		
		ECPoint c1 = cipher.Init_enc(sm2, userKey);
		cipher.Encrypt(source);
		byte[] c3 = new byte[32];
		cipher.Dofinal(c3);
		
//		DERInteger x = new DERInteger(c1.getX().toBigInteger());
//		DERInteger y = new DERInteger(c1.getY().toBigInteger());
		String x = c1.getX().toBigInteger().toString(16);
		String y = c1.getY().toBigInteger().toString(16);
		StringBuffer sbX = new StringBuffer(x);
		StringBuffer sbY = new StringBuffer(y);
		while (x.length() < 64) {
			sbX.append("0" + sbX.toString());
		}
		while (y.length() < 64) {
			sbY.append("0" + sbY.toString());
		}
		sb.append(sbX.toString());
		sb.append(sbY.toString());
		sb.append(Util.byteToHex(source));
		sb.append(Util.byteToHex(c3));
		return sb.toString();
	}
	
	/**
	 * <b>描述:数据解密</b> 
	 * @author zjc
	 * @return
	 * @throws IOException
	 */
	@SuppressWarnings("deprecation")
	public static String decrypt(String prik, String encryStr) throws IOException
	{
		if (encryStr == null || encryStr.length() == 0){
			return null;
		}
		byte[] privateKey = Util.hexToByte(prik);
		byte[] encryptedData = Util.hexToByte(encryStr);
		String data = Util.byteToHex(encryptedData);
		byte[] c1Bytesx = Util.hexToByte(data.substring(0,c1XYL));
		byte[] c1Bytesy = Util.hexToByte(data.substring(c1XYL,c1XYL<<1));
		byte[] c2 = Util.hexToByte(data.substring(c1XYL<<1,data.length()-c1XYL));
		byte[] c3 = Util.hexToByte(data.substring(data.length()-c3L));
		SM2 sm2 = SM2.Instance();
		BigInteger userD = new BigInteger(1, privateKey);
		ECPoint c1 = new ECPoint.Fp(new ECCurve.Fp(sm2.ecc_p, sm2.ecc_a, sm2.ecc_b),
				new Fp(sm2.ecc_p, Util.byteConvertInteger(c1Bytesx)), 
				new Fp(sm2.ecc_p, Util.byteConvertInteger(c1Bytesy)));
		Cipher cipher = new Cipher();
		cipher.Init_dec(userD, c1);
		cipher.Decrypt(c2);
		cipher.Dofinal(c3);
		String result = new String(c2,"UTF-8");
		return result;
	}
	
	public static String[]  sm3decrypt(String password){
		String[] strPass={password,password};
		return strPass;
	}
}
