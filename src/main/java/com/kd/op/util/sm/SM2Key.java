/**  
* @版权所有:北京科东电力控制系统有限责任公司 
* @Filename: SM2Key.java 
* @Package sm 
* @author zjc    
* @date 创建于 2017-1-18 下午10:21:49
* @version V1.0
* Last Modified: 2017-1-18
* History:  时间           user    描述
*
*/
package com.kd.op.util.sm;

import java.io.Serializable;

/**
 *<b>概述</b>：<br>
 *sm2秘钥对
 *<p>
 *<b>功能</b>：<br>
 *
 *<p>
 *<b>@author zjc</b>
 */
public class SM2Key implements Serializable{
	/**
	 * 
	 */
	private static final long serialVersionUID = -1195778555439322733L;
	private String pubKey;
	private String priKey;
	//密码加密所需要的密钥，固定不变，不能修改
	public final static String DBPrivKey = "00b1fc2f45f13ef4b1f96216f46808d2e13aef36b2a1a65409ea94f5ace4aad0";
	public final static String DBPubKey = "0491a08631c8289e69b5c8240d2005359229041a0f6105d11e4fe6173d11457133c780d2891af0008841e550165e0c957beda428bf8b86dad98a7e8eb3751f5775";
	/**
	 * @param pubKey
	 * @param priKey
	 */
	public SM2Key(String pubKey, String priKey) {
		super();
		this.pubKey = pubKey;
		this.priKey = priKey;
	}
	public String getPubKey() {
		return pubKey;
	}
	public void setPubKey(String pubKey) {
		this.pubKey = pubKey;
	}
	public String getPriKey() {
		return priKey;
	}
	public void setPriKey(String priKey) {
		this.priKey = priKey;
	}
	
}
