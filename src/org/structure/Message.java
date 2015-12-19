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
	private String message;
	private String signature;
	private String salt;
	private String time;
	private long movingFactor;
	private boolean isNullMessage = false;
	private PrivateKey localPrivateKey;
	private PublicKey remotePublicKey;
	private SecretKey messageSecretKey;
	
	
	public Message(String message_string, SecretKey messageSecretKey, PrivateKey localPrivateKey, boolean usesTime, long movingFactor_long) throws InvalidKeyException, NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeySpecException, SignatureException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException
	{
		this.movingFactor = movingFactor_long; //Save Moving factor for this Message
		
		// Get time parameter, if algorithm uses time.
		if(usesTime)
			this.time = new Clock().getTime();
		else
			this.time = "";
		
		this.localPrivateKey = localPrivateKey; //Save the local private key for this message
		this.salt = Base64.encodeBase64String(AesCrypt.getSalt()); // Get Salt and save it for this message
		this.messageSecretKey = messageSecretKey; //Save messageSecretKey to derive SecretKey for this message later.
		SecretKey key = AesCrypt.generateMessageKey(this.messageSecretKey, Base64.decodeBase64(this.salt), this.time, this.movingFactor); //Create & save this message's key.
		this.signature = Authenticator.sign(message_string, this.localPrivateKey); //Get and Save the signature
		this.message = AesCrypt.encrypt(message_string, key); //Create the encrypted message text.
	}
	
	public Message() // Create a null message Object.
	{
		isNullMessage = true;
	}
	
	public Message(String json, SecretKey messageSecretKey, PublicKey remotePublicKey, boolean usesTime, long movingFactor) throws ParseException, InvalidKeyException, NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeySpecException
	{
		this.movingFactor = movingFactor; //Save moving factor for this message.
		
		//Get time parameter, if algorithm uses it.
		if(usesTime)
			this.time = new Clock().getTime();
		else
			this.time = "";
		this.remotePublicKey = remotePublicKey; //Save the remote Public key for verification.
		this.messageSecretKey = messageSecretKey;
		
		this.fromString(json); //Convert the JSON string to message object
	}

	public String getMessage() throws InvalidKeyException, NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, SignatureException, InvalidAlgorithmParameterException
	{
		SecretKey key = AesCrypt.generateMessageKey(this.messageSecretKey, Base64.decodeBase64(this.salt), this.time, this.movingFactor); //Generate and save the Key for this message.
		String message_string = AesCrypt.decrypt(this.message, key); //Decrypt message.
		if(!Authenticator.verify(message_string, this.signature, this.remotePublicKey)) //Authenticate if message is the same as the signature, and destroy if it isn't verified.
		{
			this.destroy(); //Destroy.
			message_string = "Corrupted Message Object. Message Object is made null."; //return message output.
		}
		return message_string;
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
	
	public boolean isNullMessage()
	{
		return this.isNullMessage;
	}
	
	public void destroy()
	{
		this.message = "";
		this.message = null;
		this.signature = "";
		this.signature = null;
		this.salt = "";
		this.salt = null;
		this.localPrivateKey = null;
		this.remotePublicKey = null;
		this.messageSecretKey = null;
		this.movingFactor = 0;
		this.isNullMessage = true;
	}
}
