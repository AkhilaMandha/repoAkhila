package sharedkeyencryptpackage;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Random;

	    
public class sharedkeyencryptclass {
	
	
	
		    public static String encryptionUsingSharedKey(String originalData) {
	        try {
	            // Load the private key for signing and public key for encrypting the AES key
	            PrivateKey privateKey1 = loadPrivateKey("D:\\cryptographytask\\private_key.pem");
	            PublicKey publicKey = loadPublicKey("D:\\cryptographytask\\secondpublic_key.pem");

	            // Generate digital signature of the original data
	            String generatedSign = generateSignature(originalData, privateKey1);

	            // Generate AES shared key for data encryption
	            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
	            keyGen.init(256);
	            SecretKey secretKey = keyGen.generateKey();

	            // Generate IV for AES encryption
	            byte[] iv = new byte[16];
	            new SecureRandom().nextBytes(iv);
	            IvParameterSpec ivParams = new IvParameterSpec(iv);

	            // Encrypt data using AES
	            Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
	            aesCipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParams);
	            byte[] encryptedData = aesCipher.doFinal(originalData.getBytes());

	            // Encrypt the AES key with RSA public key
	            String encryptedSharedKey = encryptSharedKey(secretKey, publicKey);

	            // Encode the encrypted data and IV to Base64
	            String encodedIv = Base64.getEncoder().encodeToString(iv);
	            String encodedEncryptedData = Base64.getEncoder().encodeToString(encryptedData);

	            System.out.println("Encrypted Data: " + encodedEncryptedData);
	            System.out.println("Decrypted Data: " + decryptData(encryptedData, secretKey, iv));

	            // Return formatted output with the signature, encrypted key, and encrypted data
	            return generatedSign + ":" + encryptedSharedKey + ":" + encodedEncryptedData;
	        } catch (Exception e) {
	            e.printStackTrace();
	        }
	        return "";
	    }

	    private static String generateSignature(String data, PrivateKey privateKey) throws Exception {
	        Signature signature = Signature.getInstance("SHA256withRSA");
	        signature.initSign(privateKey);
	        signature.update(data.getBytes());
	        return Base64.getEncoder().encodeToString(signature.sign());
	    }

	    private static String encryptSharedKey(SecretKey sharedKey, PublicKey publicKey) throws Exception {
	        Cipher rsaCipher = Cipher.getInstance("RSA");
	        rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);
	        byte[] encryptedKeyBytes = rsaCipher.doFinal(sharedKey.getEncoded());
	        return Base64.getEncoder().encodeToString(encryptedKeyBytes);
	    }

	    private static String decryptData(byte[] encryptedData, SecretKey secretKey, byte[] iv) throws Exception {
	        Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
	        aesCipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
	        return new String(aesCipher.doFinal(encryptedData));
	    }

	    // Placeholder for key loading methods
	    private static PrivateKey loadPrivateKey(String path) { /* Load private key from path */ return null; }
	    private static PublicKey loadPublicKey(String path) { /* Load public key from path */ return null; }
	}



