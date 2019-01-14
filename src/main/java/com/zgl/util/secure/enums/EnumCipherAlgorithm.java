package com.zgl.util.secure.enums;

public enum EnumCipherAlgorithm {
	/**
	 *
	 * "算法/模式/补码方式"
	 *
	 * 对称加密算法：
	 * DES
	 * DESede
	 * AES
	 * IDEA
	 *
	 * 非对称加密算法：
	 * RSA
	 *
	 * 模式：
	 * ECB---Electronic Codebook block mode(项目中常用)
	 * CBC---Cipher Block Chaining mode(JS中默认模式).
	 * OFB---Output Feedback block mode
	 * CTRGladman---Counter block mode compatible with  Dr Brian Gladman fileenc.c
	 * CTR---Counter block mode
	 * CFB---Cipher Feedback block mode

	 *
	 * 补码方式：
	 * Pkcs7---PKCS #5/7 padding strategy(项目中常用，JS中默认补码方式)
	 * AnsiX923---ANSI X.923 padding strategy
	 * Iso10126---ISO 10126 padding strategy
	 * Iso97971---ISO/IEC 9797-1 Padding Method 2
	 * NoPadding---A noop padding strategy
	 * ZeroPadding---Zero padding strategy
	 */
	DES_ECB_PKCS5Padding(EnumKeyAlgorithm.DES,"DES/ECB/PKCS5Padding"),
//	PBEWITHMD5andDES_ECB_PKCS1Padding(EnumKeyAlgorithm.PBEWITHMD5andDES,"PBEWITHMD5andDES/ECB/PKCS1Padding"),
	DESede_ECB_PKCS5Padding(EnumKeyAlgorithm.DESede,"DESede/ECB/PKCS5Padding"),
	AES_ECB_PKCS5Padding(EnumKeyAlgorithm.AES,"AES/ECB/PKCS5Padding"),
	IDEA_ECB_PKCS5Padding(EnumKeyAlgorithm.IDEA,"IDEA/ECB/PKCS5Padding"),

	RSA_ECB_PKCS1Padding(EnumKeyAlgorithm.RSA,"RSA/ECB/PKCS1Padding"),
//	DSA_ECB_PKCS1Padding(EnumKeyAlgorithm.DSA,"DSA/ECB/PKCS1Padding"),
	ElGamal_ECB_PKCS1Padding(EnumKeyAlgorithm.ElGamal,"ElGamal/ECB/PKCS1Padding"),
	;
	
	private EnumKeyAlgorithm keyAlgorithm;
	private String value;
	public String getValue() {
		return value;
	}
	EnumCipherAlgorithm(EnumKeyAlgorithm keyAlgorithm,String value){
		this.keyAlgorithm = keyAlgorithm;
		this.value = value;
	}
	public EnumKeyAlgorithm getKeyAlgorithm() {
		return keyAlgorithm;
	}
}
