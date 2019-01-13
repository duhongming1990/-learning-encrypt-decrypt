package com.zgl.util.secure.util;

import com.zgl.util.secure.enums.EnumAuthCodeAlgorithm;
import com.zgl.util.secure.enums.EnumKeyAlgorithm;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;

@Slf4j
public class KeyUtil {

	public static SecretKey generateKey(EnumAuthCodeAlgorithm authCodeAlgorithm) throws NoSuchAlgorithmException, NoSuchProviderException {
		Security.addProvider(new BouncyCastleProvider());
		KeyGenerator keyGen = KeyGenerator.getInstance(authCodeAlgorithm.name(),"BC");
		return keyGen.generateKey();
	}

	public static SecretKey generateKey(EnumKeyAlgorithm keyAlgorithm, Integer keySize) throws NoSuchAlgorithmException, NoSuchProviderException {

		Security.addProvider(new BouncyCastleProvider());

		KeyGenerator keyGen = KeyGenerator.getInstance(keyAlgorithm.name(),"BC");

		log.debug("security provider:{}",keyGen.getProvider());
		switch (keyAlgorithm) {
			case DES:
				keyGen.init(keySize == null ? 56 :keySize);break;
			case DESede:
				keyGen.init(keySize == null ? 168 :keySize);break;
			case AES://128、192、256
			case IDEA:
				keyGen.init(keySize == null ? 128 :keySize);break;
			default:
				throw new NoSuchAlgorithmException();
		}
		return keyGen.generateKey();
	}
	
	public static KeyPair generateKeyPair(EnumKeyAlgorithm keyAlgorithm,Integer keySize) throws Exception{

		Security.addProvider(new BouncyCastleProvider());
	
		switch (keyAlgorithm) {
			case RSA:
			case DSA:
			{
				KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(keyAlgorithm.name(),"BC");
				log.debug("security provider:{}",keyPairGen.getProvider());
				keyPairGen.initialize(keySize == null ? 1024 :keySize); 
				return keyPairGen.generateKeyPair(); 
			}
			case ElGamal:
			{
				AlgorithmParameterGenerator apg = AlgorithmParameterGenerator.getInstance(keyAlgorithm.name(),"BC");
				apg.init(keySize == null ? 256 :keySize);
				AlgorithmParameters parameters = apg.generateParameters();
				DHParameterSpec elParameterSpec = parameters.getParameterSpec(DHParameterSpec.class);
				KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(keyAlgorithm.name(),"BC");
				log.debug("security provider:{}",keyPairGenerator.getProvider());
				keyPairGenerator.initialize(elParameterSpec, new SecureRandom());
				return keyPairGenerator.generateKeyPair();
				
			}
			case ECDSA:	
			{
				BigInteger p = new BigInteger("883432555555365666666666666666666666666666666666666666666666666662");
				ECFieldFp ecFieldFp = new ECFieldFp(p);
				BigInteger a = new BigInteger("7ffffffffffffffffffffffffffffff7ffffffffffffffff80000000007fffffffc", 16);
				BigInteger b = new BigInteger("7fffffffff2352362466577fffffff7657567f80000087976976934537fff233453",16);
				EllipticCurve ellipticCurve = new EllipticCurve(ecFieldFp, a, b);
				BigInteger x = new BigInteger("110243253258329580234023842384592859238592385923895823955235235");
				BigInteger y = new BigInteger("110243253258329423905600223426-92859238592385923895823955235235");
				ECPoint g = new ECPoint(x, y);
				BigInteger n = new BigInteger("594908395929308592804890258920859767623578085934895200818985368340");
				ECParameterSpec ecParameterSpec = new ECParameterSpec(ellipticCurve, g, n, 1);
				KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(keyAlgorithm.name(),"BC");
				log.debug("security provider:{}",keyPairGenerator.getProvider());
				keyPairGenerator.initialize(ecParameterSpec,new SecureRandom());
				return keyPairGenerator.generateKeyPair();
			}
			default:
				throw new NoSuchAlgorithmException();
		}
	
	}
}
