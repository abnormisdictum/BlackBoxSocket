package org.threads;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.concurrent.LinkedBlockingQueue;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import org.json.simple.parser.ParseException;
import org.socket.BlackBoxSocket;
import org.structure.Message;

public class BlackBoxServerThread extends Thread 
{
	private ServerSocket server;
	private Socket socket;
	private BlackBoxSocket blackBox;

	private SecretKey messageSecretKey;
	private PublicKey remotePublicKey;
	private String endSessionString;
	private long movingFactor;
	private boolean useTime;
	
	private LinkedBlockingQueue<Message> inQueue;
	private LinkedBlockingQueue<Message> outQueue;
	
	public BlackBoxServerThread(int port) throws IOException, InvalidKeyException, NumberFormatException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException
	{
		this.server = new ServerSocket(port);
		this.socket = this.server.accept();
		this.blackBox = new BlackBoxSocket(this.socket, false, true, true);
		this.messageSecretKey = blackBox.getMessageSecretKey();
		this.remotePublicKey = blackBox.getRemotePublicKey();
		this.endSessionString = blackBox.getEndSessionString();
		this.movingFactor = blackBox.getMovingFactor();
		this.useTime = blackBox.getUseTimeParameter();
		
		this.inQueue = new LinkedBlockingQueue<Message>();
		this.outQueue = new LinkedBlockingQueue<Message>();
	}
	
	public void run()
	{
		String ret;
		try {
			while(!(ret = this.blackBox.readMessage()).equals(this.endSessionString))
			{
				this.inQueue.offer(new Message(ret, this.messageSecretKey, this.remotePublicKey, this.useTime, this.movingFactor));
				while(this.outQueue.size()>0)
				{
					this.blackBox.sendMessage(this.outQueue.poll());
				}
			}
			this.blackBox.destroy(true);
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException
				| BadPaddingException | InvalidAlgorithmParameterException | IOException | ParseException | InvalidKeySpecException e) {
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
}
