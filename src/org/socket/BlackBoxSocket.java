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

import org.apache.commons.math3.random.RandomDataGenerator;
import org.structure.AesCrypt;
import org.structure.Message;
import org.structure.RsaCrypt;

public class BlackBoxSocket 
{
	private String END_SESSION_STRING = "DESTROY_SESSION";
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
	private boolean useTime;
	
	private long movingFactor;
	private long movingFactor_increment;
	
	public BlackBoxSocket(Socket socket, boolean isClient, boolean isClientControlled, boolean useTime) throws IOException, NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, NumberFormatException, InvalidAlgorithmParameterException
	{
		this.socket = socket; //Get Socket object that the BlackBoxSocket is supposed to sit upon.
		this.isClient = isClient; //Whether or not this instance of BlackBoxSocket is a client.
		this.isClientControlled = isClientControlled; //Whether this instance is a Client controlled instance. i.e. are the MessageSecretKey and OuterLayerSecretKey given by Client.
		this.useTime = useTime;
		
		this.inStream_raw = this.socket.getInputStream(); // Get the Socket's input stream.
		this.outStream_raw = this.socket.getOutputStream(); // Get the Socket's output stream.
		this.inStream = new DataInputStream(this.inStream_raw); //Convert SocketInputStrean to DataInputStream. This throws ClassException when done directly hence done in two steps.
		this.outStream = new DataOutputStream(this.outStream_raw); //Convert SocketOutputStrean to DataOutputStream. This throws ClassException when done directly hence done in two steps.
		
		KeyPair kp = RsaCrypt.generateKeyPair(); //Generate KeyPair.
		this.localPrivateKey = kp.getPrivate(); //Set client's Private Key.
		this.localPublicKey = kp.getPublic(); //Set Client's Public Key.
		
		if(this.isClient)
			initAsClient(); //Init as Client.
		else if(!this.isClient)
			initAsServer(); //Init as Server
	}
	
	//Defines method for Client instance.
	private void initAsClient() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, NumberFormatException, InvalidAlgorithmParameterException
	{
		this.outStream.writeUTF(RsaCrypt.convertToString(this.localPublicKey)); //Send client public key for verification and AES Key exchange
		this.remotePublicKey = RsaCrypt.convertFromString((String)this.inStream.readUTF()); //Get Server's Public Key.
		this.outStream.writeBoolean(isClientControlled); //Inform the server who is generating the Message & OuterLayer SecretKeys.
		
		if(!this.isClientControlled) //If Key Generation isn't controlled by client, get Message and OuterLayer SecretKeys from server.
		{
			this.messageSecretKey = RsaCrypt.unwrapKey((String)this.inStream.readUTF(), this.localPrivateKey); //Get Message SecretKey from server.
			this.outerLayerSecretKey = RsaCrypt.unwrapKey((String)this.inStream.readUTF(), this.localPrivateKey); //Get OuterLayer SecretKey from server.
			String movingFactor = AesCrypt.decrypt(this.inStream.readUTF(), this.outerLayerSecretKey); //Get string for OTP movingFactor
			this.movingFactor = Long.parseLong(movingFactor); //Convert Moving factor to long for calculations.
			String movingFactor_increment = AesCrypt.decrypt(this.inStream.readUTF(), this.outerLayerSecretKey); //Get Moving factor increment value.
			this.movingFactor_increment = Long.parseLong(movingFactor_increment); //Convert to long for calculations.
			this.useTime = this.inStream.readBoolean(); //Get whether to useTime in messages.
		}
		
		if(this.isClientControlled) //If Key generation is controlled by client, Generate Message and OuterLayer SecretKeys and send them to server.
		{
			RandomDataGenerator rdg = new RandomDataGenerator(); //create generator to generate secure long values.
			this.movingFactor = rdg.nextSecureLong(0, Long.MAX_VALUE/16); //Create MovingFactor.
			this.movingFactor_increment = rdg.nextSecureLong(0, 200); //Create moving factor increment.
			this.messageSecretKey = AesCrypt.generateKey(); //Generate messageSecretKey
			this.outerLayerSecretKey = AesCrypt.generateKey(); //Generate outerLayerSecretKey
			this.outStream.writeUTF(RsaCrypt.wrapKey(this.messageSecretKey, this.remotePublicKey)); //Send messageSecretKey to server.
			this.outStream.writeUTF(RsaCrypt.wrapKey(this.outerLayerSecretKey, this.remotePublicKey)); //Send outerLayerSecretKey to server.
			this.outStream.writeUTF(AesCrypt.encrypt(String.valueOf(this.movingFactor), this.outerLayerSecretKey)); //Send movingFactor.
			this.outStream.writeUTF(AesCrypt.encrypt(String.valueOf(this.movingFactor_increment), this.outerLayerSecretKey)); // Send movingFactor increment.
			this.outStream.writeBoolean(useTime); //Send time usage parameter.
		}
	}
	 
	// Defines method for Server instance.
	private void initAsServer() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException
	{
		this.remotePublicKey = RsaCrypt.convertFromString((String)this.inStream.readUTF()); //Get Clients public key.
		this.outStream.writeUTF(RsaCrypt.convertToString(localPublicKey)); //Send server's public key.
		this.isClientControlled = this.inStream.readBoolean(); //Get whether or not instance is client controlled.
		
		if(!this.isClientControlled) //If Key generation isn't controlled by client, Generate Message and OuterLayer SecretKeys and send them to client.
		{
			RandomDataGenerator rdg = new RandomDataGenerator(); //Generator to generate secure long number.
			this.movingFactor = rdg.nextSecureLong(0, Long.MAX_VALUE/16); //Generate moving factor.
			this.movingFactor_increment = rdg.nextSecureLong(0, 200); //Generate moving factor increment value.
			this.messageSecretKey = AesCrypt.generateKey(); //generate messageSecretKey
			this.outerLayerSecretKey = AesCrypt.generateKey(); //generate outerLayerSecretKey.
			this.outStream.writeUTF(RsaCrypt.wrapKey(this.messageSecretKey, this.remotePublicKey)); //Send messageSecretKey to client.
			this.outStream.writeUTF(RsaCrypt.wrapKey(this.outerLayerSecretKey, this.remotePublicKey)); //Send outerLayerSecretKey to client.
			this.outStream.writeUTF(AesCrypt.encrypt(String.valueOf(this.movingFactor), this.outerLayerSecretKey)); //Send movingFactor.
			this.outStream.writeUTF(AesCrypt.encrypt(String.valueOf(this.movingFactor_increment), this.outerLayerSecretKey)); //Send movingFactor increment.
			this.outStream.writeBoolean(useTime); //Send time usage parameter.
		}
		
		if(this.isClientControlled) //If Key Generation is controlled by client, get Message and OuterLayer SecretKeys from client.
		{
			
			this.messageSecretKey = RsaCrypt.unwrapKey((String)this.inStream.readUTF(), this.localPrivateKey); //Get Message SecretKey from server.
			this.outerLayerSecretKey = RsaCrypt.unwrapKey((String)this.inStream.readUTF(), this.localPrivateKey); //Get OuterLayer SecretKey from server.
			String movingFactor = AesCrypt.decrypt(this.inStream.readUTF(), this.outerLayerSecretKey); //Get movingFactor value from client.
			this.movingFactor = Long.parseLong(movingFactor); //Convert to long for addition operation.
			String movingFactor_increment = AesCrypt.decrypt(this.inStream.readUTF(), this.outerLayerSecretKey); //Get movingFactor increment value.
			this.movingFactor_increment = Long.parseLong(movingFactor_increment); //Convert to long for addition.
			this.useTime = this.inStream.readBoolean(); //Get whether to useTime in messages.
		}
	}
	
	//Read a message string and return the JSON Message string after decryption.
	public String readMessage() throws IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException
	{
		String revieved = this.inStream.readUTF(); //Read string.
		String json = AesCrypt.decrypt(revieved, this.outerLayerSecretKey); //Decrypt the outer Layer.
		this.movingFactor += this.movingFactor_increment; //increment the movingFactor.
		return json; //return the JSON String.
	}
	
	//Send a message object
	public void sendMessage(Message mes) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, IOException
	{
		String json = mes.toString(); //Get Message object JSON string.
		outStream.writeUTF(AesCrypt.encrypt(json, this.outerLayerSecretKey)); //Encrypt it to the outerlayer.
		this.movingFactor += this.movingFactor_increment; //increment moving factor.
	}
	
	//Send Terminate session request
	public void sendEndSession() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, IOException
	{
		outStream.writeUTF(AesCrypt.encrypt(this.END_SESSION_STRING, this.outerLayerSecretKey));
		this.movingFactor += this.movingFactor_increment;
	}
	
	//Destroy the BlackBoxSocket instance.
	public void destroy(boolean sessionHasEnded) throws IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException
	{
		if(!sessionHasEnded)
			sendEndSession(); //Send request to terminate session, if it isn't already terminated.
		
		this.socket.close(); //close sockets.
		this.inStream.close(); //Close stream
		this.outStream.close(); //Close stream.
		
		//Null all objects.
		this.socket = null;
		this.inStream = null;
		this.outStream = null;
		this.localPrivateKey = null;
		this.localPublicKey = null;
		this.remotePublicKey = null;
		this.messageSecretKey = null;
		this.outerLayerSecretKey = null;
		this.isClientControlled = false;
		this.isClient = false;
	}
	
	
	//Getter functions.
	public SecretKey getOuterLayerSecretKey()
	{
		return this.outerLayerSecretKey;
	}
	
	public SecretKey getMessageSecretKey()
	{
		return this.messageSecretKey;
	}
	
	public PublicKey getLocalPublicKey()
	{
		return this.localPublicKey;
	}
	
	public PrivateKey getLocalPrivateKey()
	{
		return this.localPrivateKey;
	}
	
	public PublicKey getRemotePublicKey()
	{
		return this.remotePublicKey;
	}
	
	public long getMovingFactor() //Return the moving factor.
	{
		return this.movingFactor;
	}
	
	public long getPreviousMovingFactor() //Return the previous moving factor, since the moving factor is incremented when readMessage is called.s
	{
		return this.movingFactor-=this.movingFactor_increment;
	}
	
	public boolean isClientControlled()
	{
		return isClientControlled;
	}
	
	public boolean isClient()
	{
		return isClient;
	}
	
	public String getEndSessionString()
	{
		return this.END_SESSION_STRING;
	}
	
	public boolean getUseTimeParameter()
	{
		return this.useTime;
	}
}
