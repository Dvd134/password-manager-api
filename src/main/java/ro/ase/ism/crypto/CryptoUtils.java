package ro.ase.ism.crypto;

import java.util.Base64;

public class CryptoUtils {
	
	public static String byteToBase64(byte[] array) {

        return Base64.getEncoder().encodeToString(array);
    }
}
