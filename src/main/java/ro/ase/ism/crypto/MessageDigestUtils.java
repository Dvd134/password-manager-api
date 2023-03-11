package ro.ase.ism.crypto;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class MessageDigestUtils {
	
	public static byte[] getStringHash(String value, String algorithm) throws NoSuchAlgorithmException {
		
		byte[] hashValue = null;
		
		MessageDigest messageDigest = MessageDigest.getInstance(algorithm);
		hashValue = messageDigest.digest(value.getBytes());
		
		return hashValue;
	}
}
