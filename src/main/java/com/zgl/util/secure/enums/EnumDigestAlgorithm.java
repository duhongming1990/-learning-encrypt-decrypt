package com.zgl.util.secure.enums;

public enum EnumDigestAlgorithm {
	//JDK实现
	MD2("MD2"),
	//BC实现
	MD4("MD4"),
	//JDK实现
	MD5("MD5"),

	//JDK实现
	SHA1("SHA-1"),
	//BC实现
	SHA224("SHA-224"),
	//JDK实现
	SHA256("SHA-256"),
	//JDK实现
	SHA384("SHA-384"),
	//JDK实现
	SHA512("SHA-512");


	
	private String value;
	public String getValue() {
		return value;
	}
	
	EnumDigestAlgorithm(String value){
		this.value = value;
	}
	
	
	
}
