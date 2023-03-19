package ro.ase.ism.entities;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

import ro.ase.ism.crypto.AESUtils;

public class Account {
	
	private String id;
	private String username;
	private String password;
	private ArrayList<String> tags;
	private String domain;
	
	public Account(String id, String username, String password, ArrayList<String> tags, String domain, String clientSecret) throws InvalidKeyException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, IllegalBlockSizeException, InvalidKeySpecException, BadPaddingException {
		
		AESUtils aesUtils = new AESUtils();
		
		this.id = aesUtils.encrypt(clientSecret, id);
		this.username = aesUtils.encrypt(clientSecret, username);
		this.password = aesUtils.encrypt(clientSecret, password);
		this.tags = new ArrayList<>();
		for(String tag : tags) {
			
			this.tags.add(aesUtils.encrypt(clientSecret, tag));
		}
		this.domain = aesUtils.encrypt(clientSecret, domain);
	}
	
	public Account(String username, String password, String clientSecret) throws InvalidKeyException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, IllegalBlockSizeException, InvalidKeySpecException, BadPaddingException {
		
		AESUtils aesUtils = new AESUtils();
		
		this.username = aesUtils.encrypt(clientSecret, username);
		this.password = aesUtils.encrypt(clientSecret, password);
	}

	public String getId() {
		
		return id;
	}

	public String getUsername() {
		
		return username;
	}

	public String getPassword() {
		
		return password;
	}

	public ArrayList<String> getTags() {
		
		return tags;
	}

	public String getDomain() {
		
		return domain;
	}
}
