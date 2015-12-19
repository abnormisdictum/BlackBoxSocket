package org.threads;

import java.io.IOException;
import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.util.concurrent.LinkedBlockingQueue;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import org.socket.BlackBoxSocket;
import org.structure.Message;

public class BlackBoxClientThread extends Thread {
	
	private Socket socket;
	private BlackBoxSocket blackBox;

	private SecretKey messageSecretKey;
	private PublicKey remotePublicKey;
	private PrivateKey localPrivateKey;
	private boolean useTime;
	private long movingFactor;
	
	private LinkedBlockingQueue<Message> inQueue;
	private LinkedBlockingQueue<Message> outQueue;
	
	public BlackBoxClientThread(String host, int port, boolean useTime) throws IOException, InvalidKeyException, NumberFormatException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException
	{
		this.socket = new Socket(host, port);
		this.blackBox = new BlackBoxSocket(this.socket, true, true, useTime);
		this.messageSecretKey = blackBox.getMessageSecretKey();
		this.remotePublicKey = blackBox.getRemotePublicKey();
		this.localPrivateKey = blackBox.getLocalPrivateKey();
		this.movingFactor = blackBox.getMovingFactor();
		this.useTime = blackBox.getUseTimeParameter();
		
		this.inQueue = new LinkedBlockingQueue<Message>();
		this.outQueue = new LinkedBlockingQueue<Message>();
	}
	
	public void run()
	{
		try {
			while(!this.outQueue.peek().isNullMessage())
			{
				this.inQueue.offer(new Message(blackBox.readMessage(), this.messageSecretKey, this.localPrivateKey, this.useTime, this.movingFactor));
				while(this.outQueue.size()>0)
				{
					this.blackBox.sendMessage(this.outQueue.poll());
				}
			}
			this.blackBox.destroy(false);
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException
				| BadPaddingException | InvalidAlgorithmParameterException | IOException | InvalidKeySpecException | SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	public SecretKey getMessageSecretKey()
	{
		return this.messageSecretKey;
	}
	
	public PublicKey getRemotePublicKey()
	{
		return this.remotePublicKey;
	}
	
	public PrivateKey getLocalPrivateKey()
	{
		return this.localPrivateKey;
	}
	
	public LinkedBlockingQueue<Message> getInQueue()
	{
		return this.inQueue;
	}
	
	public LinkedBlockingQueue<Message> getOutQueue()
	{
		return this.outQueue;
	}
	
	public boolean usesTime()
	{
		return this.useTime;
	}
	
	public long getMovingFactor()
	{
		return movingFactor;
	}
}
