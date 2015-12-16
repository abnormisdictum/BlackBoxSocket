package org.structure;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import org.apache.commons.codec.binary.Base64;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

public class Message 
{
	public String message;
	public String signature;
	public String salt;
	public String time;
	
	public Message(String json, String time) throws ParseException
	{
		this.time = time;
		this.fromString(json);
	}
	
	public Message(String message, SecretKey m_sk, PrivateKey m_pk, String time) throws InvalidKeyException, NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeySpecException, SignatureException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException
	{
		this.time = time;
		this.setMessage(message, m_sk, m_pk);
	}
	
	private String setMessage(String message, SecretKey m_sk, PrivateKey m_pk) throws InvalidKeyException, NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeySpecException, SignatureException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException
	{
		byte[] salt = AesCrypt.getSalt();
		this.salt = Base64.encodeBase64String(salt);
		SecretKey sk = AesCrypt.generateMessageKey(m_sk, salt, this.time);
		this.signature = Authenticator.sign(message, m_pk);
		this.message = AesCrypt.encrypt(message, sk);
		return this.toString();
	}

	public String getMessage(SecretKey m_sk, PublicKey m_pk) throws InvalidKeyException, NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, SignatureException, InvalidAlgorithmParameterException
	{
		SecretKey sk = AesCrypt.generateMessageKey(m_sk, Base64.decodeBase64(salt), this.time);
		String message = AesCrypt.decrypt(this.message, sk);
		if(Authenticator.verify(message, signature, m_pk)==false)
		{
			message="Corrupted Message. Message object has been destroyed.";
			this.message = "";
			this.message = null;
			this.signature = "";
			this.signature = null;
			this.salt = "";
			this.salt = null;
		}
		
		return message;
	}
	
	@SuppressWarnings("unchecked")
	public String toString()
	{
		JSONObject json = new JSONObject();
		json.put("Message", this.message);
		json.put("Signature", this.signature);
		json.put("Salt", this.salt);
		
		return json.toJSONString();
	}
	
	private void fromString(String json) throws ParseException
	{
		JSONObject mes = (JSONObject) new JSONParser().parse(json);
		this.message = (String) mes.get("Message");
		this.signature = (String) mes.get("Signature");
		this.salt = (String) mes.get("Salt");
	}
}
