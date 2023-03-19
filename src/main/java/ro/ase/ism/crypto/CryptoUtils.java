package ro.ase.ism.crypto;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class CryptoUtils {
	
	public static byte[] getRandomBytes(int noOfBytes, byte[] seed) throws NoSuchAlgorithmException {
		
        // SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
        SecureRandom secureRandom = new SecureRandom(); //NativePRNG
        if (seed != null) {
        	
            secureRandom.setSeed(seed);
        }
        byte[] randomBytes = new byte[noOfBytes];
        secureRandom.nextBytes(randomBytes);
        return randomBytes;
    }
	
	public static byte[] hexToByte(String hexValue) {

        byte[] data = new byte[hexValue.length()/2];
        for( int i = 0 ; i < hexValue.length() ; i += 2) {

            data[i/2] = (byte) ((Character.digit(hexValue.charAt(i), 16) << 4) + Character.digit(hexValue.charAt(i+1), 16));
        }
        return data;
    }

    public static String byteToHex(byte[] array) {

        String output = "";
        for(byte value : array) {

            output += String.format("%02x", value);
        }
        return output;
    }
	
	public static String byteToBase64(byte[] array) {

        return Base64.getEncoder().encodeToString(array);
    }
	
	public static byte[] base64ToByte(String str) {

        return Base64.getDecoder().decode(str);
    }
}
