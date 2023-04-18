package ro.ase.ism.services;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

import ro.ase.ism.crypto.AESUtils;
import ro.ase.ism.entities.Account;
import ro.ase.ism.entities.Credentials;

import java.util.logging.Logger;
import java.util.logging.Level;

public class AccountServices {
	
	private static final Logger LOGGER = Logger.getLogger(AccountServices.class.getName());
	
	public static ArrayList<Account> getAccounts(Credentials credentials, String cipherText, String domain, boolean returnFullResponse) throws InvalidKeyException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, IllegalBlockSizeException, InvalidKeySpecException, BadPaddingException {
		
		LOGGER.info("get Account started");
		
		AESUtils aesUtils = new AESUtils();
        StringBuilder plainTextContent = new StringBuilder(aesUtils.decryptFileContent(credentials.getClientSecret(), cipherText));
        
        boolean skipHeader = true;
        ArrayList<Account> accounts = new ArrayList<>();
        String[] lines = plainTextContent.toString().split(System.lineSeparator());
        
        for(String line : lines) {

            if (skipHeader) {
            	
                skipHeader = false;
                continue;
            }
            String[] fields = line.split("\\s* <---> \\s*");
            String associatedDomain = fields[3];

            if(domain == null || domain.isEmpty() || domain.equals(associatedDomain)) {

                String associatedId = returnFullResponse ? fields[0] : null;
                String associatedUsername = fields[1];
                String associatedPassword = fields[2];
                ArrayList<String> associatedTags = returnFullResponse ? new ArrayList<>(Arrays.asList(fields[4].split("~"))) : null;

//                Account account = returnFullResponse ? 
//                	new Account(associatedId, associatedUsername, associatedPassword, associatedTags, associatedDomain, credentials.getClientSecret()) : 
//                	new Account(associatedUsername, associatedPassword, credentials.getClientSecret());
                Account account = returnFullResponse ? 
                    	new Account(associatedId, associatedUsername, associatedPassword, associatedTags, associatedDomain) : 
                    	new Account(associatedUsername, associatedPassword, credentials.getClientSecret());
                
                accounts.add(account);
                
            }
        }
        return accounts;
	}
	
	public static String addAccount(Credentials credentials, String cipherText, Account account) throws InvalidKeyException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, IllegalBlockSizeException, InvalidKeySpecException, BadPaddingException {
		
		LOGGER.info("add Account started");
		
		AESUtils aesUtils = new AESUtils();
		String plainText = aesUtils.decryptFileContent(credentials.getClientSecret(), cipherText);
		
		int theComputedId = computeId(plainText);
	    StringBuilder newEntry = new StringBuilder();
	    newEntry.append(theComputedId).append(" <---> ").append(account.getUsername()).append(" <---> ").append(account.getPassword()).append(" <---> ").append(account.getDomain()).append(" <---> ").append(getStringTags(account.getTags())).append(System.lineSeparator());
		
		plainText += newEntry;
		
		return aesUtils.encryptFileContent(credentials.getClientSecret(), plainText);
	}
	
//	public static String addAccount(Credentials credentials, String cipherText, Account account) throws InvalidKeyException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, IllegalBlockSizeException, InvalidKeySpecException, BadPaddingException {
//		
//		LOGGER.info("add Account started");
//		
//		AESUtils aesUtils = new AESUtils();
//		String plainText = aesUtils.decryptFileContent(credentials.getClientSecret(), cipherText);
//		
//		int theComputedId = computeId(plainText);
//		String newEntry = theComputedId + " <---> " + account.getUsername() + " <---> " + account.getPassword() + " <---> " + account.getDomain() + " <---> " + getStringTags(account.getTags()) + System.lineSeparator();
//		
//		String[] lines = plainText.split(System.lineSeparator());
//        StringBuilder updatedContent = new StringBuilder();
//        boolean skipHeader = true;
//        boolean isKeyAdded = false;
//        int previousRowId = 0;
//        for (String row : lines) {
//            // ---SKIP FIRST LINE--- //
//            if(skipHeader) {
//                updatedContent.append(row).append(System.lineSeparator());
//                skipHeader = false;
//                // ---CHECK IF CONTENT IS EMPTY, IF TRUE ADD DIRECTLY--- //
//                if(lines.length == 1) {
//                    updatedContent.append(newEntry);
//                    isKeyAdded = true;
//                }
//                continue;
//            }
//
//            int rowId = Integer.parseInt(row.split(" <---> ")[0]);
//            if (rowId - previousRowId > 1) {
//                // ---BUILD THE LINE AND APPEND IT TO THE CONTENT--- //
//                if(!isKeyAdded) {
//                    updatedContent.append(newEntry);
//                    isKeyAdded = true;
//                }
//
//                updatedContent.append(row).append(System.lineSeparator());
//            } else {
//                updatedContent.append(row).append(System.lineSeparator());
//
//            }
//            previousRowId = rowId;
//        }
//        if(!isKeyAdded)
//            updatedContent.append(newEntry);
//		
//		return aesUtils.encryptFileContent(credentials.getClientSecret(), new String(updatedContent));
//	}
	
	public static String initAccountFile(Credentials credentials) throws InvalidKeyException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, IllegalBlockSizeException, InvalidKeySpecException, BadPaddingException {
		
		AESUtils aesUtils = new AESUtils();
		String headers = "id <---> username <---> password <---> domain <---> tags" + System.lineSeparator();
		
		return aesUtils.encryptFileContent(credentials.getClientSecret(), headers);
	}
	
	public static String getStringTags(ArrayList<String> tags) {
		
		StringBuilder value = new StringBuilder();
		int index = 0;
		for(String tag : tags) {
			
			value.append(tag);
			if(index != tags.size() - 1) {
				value.append("~");
			}
			index++;
		}
		return new String(value);
	}
	
	public static int computeId(String plainText) {
		
        String[] lines = plainText.split(System.lineSeparator());
        
        return lines.length;
	}
	
//	public static int computeId(String plainText) {
//		
//		int counter = 1;
//        int previousId = 0;
//        int currentId = 0;
//        
//        boolean skipHeader = true;
//        String[] lines = plainText.split(System.lineSeparator());
//        for(String line : lines) {
//
//            if(skipHeader) {
//                skipHeader = false;
//                continue;
//            }
//            currentId = Integer.parseInt(line.split(" <---> ")[0]);
//
//            if(currentId - previousId > 1)
//                return previousId + 1;
//
//            counter++;
//            previousId = currentId;
//        }
//        return counter;
//	}
}
