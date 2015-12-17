package org.structure;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.SecretKey;

public class Hash 
{
	private static String CHARSET = "UTF-16"; //Standardise Charset to use for String->Byte[] and Byte[]->String conversion.
	
	//Method to get HMAC using time and moving factor.
	//You can input a null or empty time String if you wish to ignore time parameter, in case of high speed communication where time step output may be different before transmission and after reception.
	public static String getHMAC(SecretKey messageSecretKey, String time, long movingFactor_long) throws NoSuchAlgorithmException, InvalidKeyException, IllegalStateException, UnsupportedEncodingException
	{
		String movingFactor = String.valueOf(movingFactor_long); //Convert long to String as to get byte[].
		Mac m = Mac.getInstance("HmacSHA256"); //Create HMAC instance
		m.init((Key)messageSecretKey); //Use given messageSecretKey
		m.update(movingFactor.getBytes(CHARSET)); //Add moving Factor.
		if(!(time.isEmpty() || time == null)) //Ignore time parameter if it is empty or null
		{
			m.update(time.getBytes(CHARSET)); //Add time
			
			//For Debug purposes, uncomment next line to see if time parameter is used.
			//System.out.println("Time String has been used");
		}
		return FormatOTP(m.doFinal()); //compute OTP.
	}
	
	//OTP computation method
	private static String FormatOTP(byte[] hmac)
	{
		//standard HOTP generation algorithm.
		int offset = hmac[19] & 0xf ; 
		int bin_code = (hmac[offset] & 0x7f) << 24 | (hmac[offset+1] & 0xff) << 16 | (hmac[offset+2] & 0xff) << 8 | (hmac[offset+3] & 0xff);
		int code = bin_code % (int)Math.pow(10, 10);
		return String.format("%015d", code);
	}

}
