package ro.ase.ism.services;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

import ro.ase.ism.entities.Account;
import ro.ase.ism.entities.Credentials;

public class AccountServices {
	
	public static ArrayList<Account> getAccounts(Credentials credentials, String domain, boolean returnFullResponse) throws InvalidKeyException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, IllegalBlockSizeException, InvalidKeySpecException, BadPaddingException {
		
        // Testing purpose:
        StringBuilder plainTextContent = new StringBuilder();
        plainTextContent.append("id <---> username <---> password <---> domain <---> tags\n");
        plainTextContent.append("1 <---> testUsername1 <---> testPassword1 <---> www.google.com <---> tag1~tag2~tag3\n");
        plainTextContent.append("2 <---> testUsername2 <---> testPassword2 <---> github.com <---> tag2~tag3~tag4\n");
        plainTextContent.append("3 <---> testUsername3 <---> testPassword3 <---> github.com <---> tag3~tag4~tag5\n");
        // end
        
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

                Account account = returnFullResponse ? 
                	new Account(associatedId, associatedUsername, associatedPassword, associatedTags, associatedDomain, credentials.getClientSecret()) : 
                	new Account(associatedUsername, associatedPassword, credentials.getClientSecret());
                
                accounts.add(account);
                
            }
        }
        return accounts;
	}
}
