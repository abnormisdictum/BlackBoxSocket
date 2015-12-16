package org.structure;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;

public class AesCrypt 
{
	private static String TRANSFORM = "AES/CBC/PKCS5Padding";
	private static int KEY_SIZE = 128;
	private static String CHARSET = "UTF-16";
	
	public static String encrypt(String data, SecretKey sk) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException
	{
		Cipher c = Cipher.getInstance(TRANSFORM);
		c.init(Cipher.ENCRYPT_MODE, sk);
		byte[] iv = c.getIV();
		return Base64.encodeBase64String(c.doFinal(data.getBytes(CHARSET)))+"<IV>"+Base64.encodeBase64String(iv);
	}
	
	public static String decrypt(String enc, SecretKey sk) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException
	{
		String[] enc_split = enc.split("<IV>");
		byte[] iv = Base64.decodeBase64(enc_split[1]);
		byte[] message = Base64.decodeBase64(enc_split[0]);
		Cipher c = Cipher.getInstance(TRANSFORM);
		c.init(Cipher.DECRYPT_MODE, sk, new IvParameterSpec(iv));
		
		return new String(c.doFinal(message), CHARSET);
	}
	
	public static SecretKey generateKey() throws NoSuchAlgorithmException
	{
		KeyGenerator kg = KeyGenerator.getInstance("AES");
		kg.init(KEY_SIZE, new SecureRandom());
		return (SecretKey)kg.generateKey();
	}
	
	public static SecretKey generateMessageKey(SecretKey messageSecretKey, byte[] salt, String time, long movingFactor) throws NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeySpecException, InvalidKeyException
	{
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		String s = new String(md.digest(Hash.getHMAC(messageSecretKey, time, movingFactor).getBytes()));
		SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
		PBEKeySpec spec = new PBEKeySpec(s.toCharArray(), salt, 65536, KEY_SIZE);
		return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
	}
	
	public static byte[] getSalt()
	{
		SecureRandom sr = new SecureRandom();
		byte[] s = new byte[16];
		sr.nextBytes(s);
		return s;
	}
}
