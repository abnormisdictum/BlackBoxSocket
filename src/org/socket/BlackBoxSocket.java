package org.socket;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import org.structure.AesCrypt;
import org.structure.Message;
import org.structure.RsaCrypt;

public class BlackBoxSocket 
{
	private Socket socket;
	private InputStream inStream_raw;
	private OutputStream outStream_raw;
	private DataInputStream inStream; //Input Stream from Server.
	private DataOutputStream outStream; //Output Stream to Server.
	
	private SecretKey outerLayerSecretKey; //Outer Layer SecretKey that encrypts the whole JSON String from messages.
	private SecretKey messageSecretKey; //Message SecretKey for generation of new Keys for each individual message using OTP algorithm.
	private PublicKey localPublicKey;	//Server's Public Key used for Authentication of Messages.
	private PrivateKey localPrivateKey; //Server's Private key used to Authenticate messages of server.
	private PublicKey remotePublicKey; //Client's Public Key sent to Server for verifying Authenticated Messages from client.
	private boolean isClient;
	private boolean isClientControlled; //Whether the Message & Outer layer key generation is done by the client.
	
	public BlackBoxSocket(Socket socket, boolean isClient, boolean isClientControlled) throws IOException, NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException
	{
		this.socket = socket;
		this.isClient = isClient;
		this.isClientControlled = isClientControlled;
		this.inStream_raw = this.socket.getInputStream();
		this.outStream_raw = this.socket.getOutputStream();
		this.inStream = new DataInputStream(this.inStream_raw);
		this.outStream = new DataOutputStream(this.outStream_raw);
		
		KeyPair kp = RsaCrypt.generateKeyPair(); //Generate KeyPair.
		this.localPrivateKey = kp.getPrivate(); //Set client's Private Key.
		this.localPublicKey = kp.getPublic(); //Set Client's Public Key.
		
		if(this.isClient)
			initAsClient();
		else if(!this.isClient)
			initAsServer();
	}
	
	private void initAsClient() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException
	{
		this.outStream.writeUTF(RsaCrypt.convertToString(this.localPublicKey));
		this.remotePublicKey = RsaCrypt.convertFromString((String)this.inStream.readUTF()); //Get Server's Public Key.
		this.outStream.writeBoolean(isClientControlled); //Inform the server who is generating the Message & OuterLayer SecretKeys.
		
		if(!this.isClientControlled) //If Key Generation isn't controlled by client, get Message and OuterLayer SecretKeys from server.
		{
			this.messageSecretKey = RsaCrypt.unwrapKey((String)this.inStream.readUTF(), this.localPrivateKey); //Get Message SecretKey from server.
			this.outerLayerSecretKey = RsaCrypt.unwrapKey((String)this.inStream.readUTF(), this.localPrivateKey); //Get OuterLayer SecretKey from server.
		}
		
		if(this.isClientControlled) //If Key generation is controlled by client, Generate Message and OuterLayer SecretKeys and send them to server.
		{
			this.messageSecretKey = AesCrypt.generateKey();
			this.outerLayerSecretKey = AesCrypt.generateKey();
			this.outStream.writeUTF(RsaCrypt.wrapKey(this.messageSecretKey, this.remotePublicKey));
			this.outStream.writeUTF(RsaCrypt.wrapKey(this.outerLayerSecretKey, this.remotePublicKey));
		}
	}
	
	private void initAsServer() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException
	{
		this.remotePublicKey = RsaCrypt.convertFromString((String)this.inStream.readUTF());
		this.outStream.writeUTF(RsaCrypt.convertToString(localPublicKey));
		this.isClientControlled = this.inStream.readBoolean();
		
		if(!this.isClientControlled) //If Key generation isn't controlled by client, Generate Message and OuterLayer SecretKeys and send them to client.
		{
			this.messageSecretKey = AesCrypt.generateKey();
			this.outerLayerSecretKey = AesCrypt.generateKey();
			this.outStream.writeUTF(RsaCrypt.wrapKey(this.messageSecretKey, this.remotePublicKey));
			this.outStream.writeUTF(RsaCrypt.wrapKey(this.outerLayerSecretKey, this.remotePublicKey));
		}
		
		if(this.isClientControlled) //If Key Generation is controlled by client, get Message and OuterLayer SecretKeys from client.
		{
			this.messageSecretKey = RsaCrypt.unwrapKey((String)this.inStream.readUTF(), this.localPrivateKey); //Get Message SecretKey from server.
			this.outerLayerSecretKey = RsaCrypt.unwrapKey((String)this.inStream.readUTF(), this.localPrivateKey); //Get OuterLayer SecretKey from server.
		}
	}
	
	public SecretKey getOuterLayerSecretKey()
	{
		return outerLayerSecretKey;
	}
	
	public SecretKey getMessageSecretKey()
	{
		return messageSecretKey;
	}
	
	public PublicKey getLocalPublicKey()
	{
		return localPublicKey;
	}
	
	public PrivateKey getLocalPrivateKey()
	{
		return localPrivateKey;
	}
	
	public PublicKey getRemotePublicKey()
	{
		return remotePublicKey;
	}
	
	public String readMessage() throws IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException
	{
		String revieved = this.inStream.readUTF();
		String json = AesCrypt.decrypt(revieved, this.outerLayerSecretKey);
		return json;
	}
	
	public void sendMessage(Message mes) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, IOException
	{
		String json = mes.toString();
		outStream.writeUTF(AesCrypt.encrypt(json, this.outerLayerSecretKey));
	}
	
	public boolean isClientControlled()
	{
		return isClientControlled;
	}
	
	public boolean isClient()
	{
		return isClient;
	}
	
	public void destroy()
	{
		this.socket = null;
		this.inStream = null;
		this.outStream = null;
		this.localPrivateKey = null;
		this.localPublicKey = null;
		this.remotePublicKey = null;
		this.messageSecretKey = null;
		this.outerLayerSecretKey = null;
		this.isClientControlled = false;
		System.gc();
	}
}
