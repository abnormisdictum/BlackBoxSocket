package org.structure;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.SecretKey;

public class Hash 
{
	public static String getHMAC(SecretKey sk, String time) throws NoSuchAlgorithmException, InvalidKeyException
	{
		Mac m = Mac.getInstance("HmacSHA256");
		m.init((Key)sk);
		return FormatOTP(m.doFinal(time.getBytes()));
	}
	
	private static String FormatOTP(byte[] hmac)
	{
		int offset = hmac[19] & 0xf ; 
		int bin_code = (hmac[offset] & 0x7f) << 24 | (hmac[offset+1] & 0xff) << 16 | (hmac[offset+2] & 0xff) << 8 | (hmac[offset+3] & 0xff);
		int code = bin_code % (int)Math.pow(10, 10);
		return String.format("%015d", code);
	}

}
