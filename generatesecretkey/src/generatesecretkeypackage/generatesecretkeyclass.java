package generatesecretkeypackage;

import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class generatesecretkeyclass {
	
	
	public static String getSecretKey() {
        try {
            // Log or process the input parameter if needed
          //  System.out.println("Input Info: " + info1);

            // Create a KeyGenerator instance for AES
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(256); // Set the key size (128, 192, or 256 bits)

            // Generate the secret key
            SecretKey secretKey = keyGenerator.generateKey();

            // Return the secret key as a Base64 encoded string
            return Base64.getEncoder().encodeToString(secretKey.getEncoded());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null; // Handle exceptions as needed
        }
	}


}
