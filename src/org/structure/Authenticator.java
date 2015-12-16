package org.structure;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

import org.apache.commons.codec.binary.Base64;

public class Authenticator 
{
	private static String CHARSET = "UTF-16";
	
	public static String sign(String message, PrivateKey pk) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, UnsupportedEncodingException
	{
		Signature sig = Signature.getInstance("SHA256withRSA");
		sig.initSign(pk);
		sig.update(message.getBytes(CHARSET));
		
		return Base64.encodeBase64String(sig.sign());
	}
	
	public static boolean verify(String message, String sign, PublicKey pk) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, UnsupportedEncodingException
	{
		Signature sig = Signature.getInstance("SHA256withRSA");
		sig.initVerify(pk);
		sig.update(message.getBytes(CHARSET));
		
		return sig.verify(Base64.decodeBase64(sign));
	}
	
	public static String sign(String message, KeyPair pk) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, UnsupportedEncodingException
	{
		return sign(message, pk.getPrivate());
	}
	
	public static boolean verify(String message, String sign, KeyPair pk) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, UnsupportedEncodingException
	{
		return verify(message, sign, pk.getPublic());
	}
}
