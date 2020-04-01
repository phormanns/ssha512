package de.jalin.ssha512;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.apache.commons.codec.binary.Base64;

public class SSHA512 {

	private static final Base64 BASE64 = new Base64();
	private static final String LABEL = "{SSHA512}";
	private static final String SALT_CHARACTERS = 
			  "abcdefghijklmnopqrstuvwxyz"
			+ "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
			+ "0123456789$_";

	public static String randomSalt() {
    	final StringBuffer buffer = new StringBuffer();
    	for (int i=0; i < 8; i++) {
    		final double randomValue = Math.random() * SALT_CHARACTERS.length() - 0.5d;
    		int randomIndex = Math.round((float)randomValue);
    		if (randomIndex < 0 || randomIndex >= SALT_CHARACTERS.length()) {
    			randomIndex = 0;
    		}
    		buffer.append(SALT_CHARACTERS.charAt(randomIndex));
    	}
    	return buffer.toString();
    }
    
	public static String createSaltedSHA512Hash(String passwd) throws NoSuchAlgorithmException {
		return createSaltedSHA512Hash(randomSalt(), passwd);
    }
    
	public static String createSaltedSHA512Hash(String salt, String passwd) throws NoSuchAlgorithmException {
		final byte[] saltBytes = salt.getBytes();
		final MessageDigest sha = MessageDigest.getInstance("SHA-512");
		sha.reset();
		sha.update(passwd.getBytes());
		sha.update(saltBytes);
		final byte[] pwHash = sha.digest();
		final byte[] hashBytes = new byte[pwHash.length + saltBytes.length];
		System.arraycopy(pwHash, 0, hashBytes, 0, pwHash.length);
		System.arraycopy(saltBytes, 0, hashBytes, pwHash.length, saltBytes.length);
		final String encode = BASE64.encodeAsString(hashBytes);
		return LABEL + new String(encode);
	}

	public static void main(String[] args) {
		if (args.length < 1) {
			System.out.println("at least one password is expected as a parameter");
			System.exit(0);
		}
		try {
			for (final String password : args) {
				System.out.println("hash for '" + password + "' is: " + createSaltedSHA512Hash(password));
			}
		} catch (NoSuchAlgorithmException e) {
			System.out.println(e.getLocalizedMessage());
		}
	}
}
