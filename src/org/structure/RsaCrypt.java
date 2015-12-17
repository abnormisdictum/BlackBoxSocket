package org.structure;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import org.apache.commons.codec.binary.Base64;

public class RsaCrypt 
{
	private static String TRANSFORM = "RSA/ECB/PKCS1Padding"; //Set Transformation type.
	private static int KEY_SIZE = 2048; //Set key length.
	
	//Wrap keys
	public static String wrapKey(SecretKey sk, PublicKey pk) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException
	{
		Cipher c = Cipher.getInstance(TRANSFORM);
		c.init(Cipher.WRAP_MODE, pk);
		return Base64.encodeBase64String(c.wrap(sk));
	}
	
	//UnrapKeys
	public static SecretKey unwrapKey(String sk, PrivateKey pk) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException
	{
		Cipher c = Cipher.getInstance(TRANSFORM);
		c.init(Cipher.UNWRAP_MODE, pk);
		return (SecretKey)c.unwrap(Base64.decodeBase64(sk), "AES", Cipher.SECRET_KEY);
	}
	
	//Generate KeyPair
	public static KeyPair generateKeyPair() throws NoSuchAlgorithmException
	{
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		kpg.initialize(KEY_SIZE, new SecureRandom());
		return kpg.generateKeyPair();
	}
	
	//Convert PublicKey to String for transmission.
	public static String convertToString(PublicKey pk)
	{
		return Base64.encodeBase64String(pk.getEncoded());
	}
	
	//Convert String to PublicKey.
	public static PublicKey convertFromString(String pk) throws NoSuchAlgorithmException, InvalidKeySpecException
	{
		X509EncodedKeySpec ks = new X509EncodedKeySpec(Base64.decodeBase64(pk));
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePublic(ks);
	}
}
