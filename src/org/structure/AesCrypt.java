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
	private static String TRANSFORM = "AES/CBC/PKCS5Padding"; //Specify Transformation type.
	private static int KEY_SIZE = 128; //Specify Key Size for key generation
	private static String CHARSET = "UTF-16"; //Standardise charset to use when converting String->Byte[]  or Byte[]->String. 
	
	//Aes Encrypt
	public static String encrypt(String data, SecretKey sk) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException
	{
		Cipher c = Cipher.getInstance(TRANSFORM);
		c.init(Cipher.ENCRYPT_MODE, sk);
		byte[] iv = c.getIV();
		return Base64.encodeBase64String(c.doFinal(data.getBytes(CHARSET)))+"<IV>"+Base64.encodeBase64String(iv); //Add IV to encoded string and split using <IV>
	}
	
	//AES Decrypt.
	public static String decrypt(String enc, SecretKey sk) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException
	{
		String[] enc_split = enc.split("<IV>"); //Split String to get IV and message data.
		byte[] iv = Base64.decodeBase64(enc_split[1]); //Convert IV to byte[]
		byte[] message = Base64.decodeBase64(enc_split[0]); //convert Message to byte[]
		Cipher c = Cipher.getInstance(TRANSFORM); //Initialise cipher.
		c.init(Cipher.DECRYPT_MODE, sk, new IvParameterSpec(iv));
		return new String(c.doFinal(message), CHARSET);
	}
	
	//Generate AES Key.
	public static SecretKey generateKey() throws NoSuchAlgorithmException
	{
		KeyGenerator kg = KeyGenerator.getInstance("AES");
		kg.init(KEY_SIZE, new SecureRandom());
		return (SecretKey)kg.generateKey();
	}
	
	//Generate Message key using OTP created using Hash Class.
	public static SecretKey generateMessageKey(SecretKey messageSecretKey, byte[] salt, String time, long movingFactor) throws NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeySpecException, InvalidKeyException
	{
		MessageDigest md = MessageDigest.getInstance("SHA-256"); //Create instance of message digest in order to create message key.
		String s = new String(md.digest(Hash.getHMAC(messageSecretKey, time, movingFactor).getBytes())); //Get message key using time and movingFactor then create it's SHA256 hash.
		SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256"); //Use created SHA256 hash to create SecretKeySpecs.
		PBEKeySpec spec = new PBEKeySpec(s.toCharArray(), salt, 65536, KEY_SIZE); //Create SecretKey using salt. 
		return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES"); //Generate message key.
	}
	
	
	//Function to create salt for MessageKey generation algorithm.
	public static byte[] getSalt()
	{
		SecureRandom sr = new SecureRandom();
		byte[] s = new byte[16];
		sr.nextBytes(s);
		return s;
	}
}
