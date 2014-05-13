import java.security.Security;
import java.util.Date;
import java.sql.Timestamp;
import javax.crypto.KeyGenerator;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class aes {
	
	public static void GetTimestamp(String info){
		System.out.println(info + new Timestamp((new Date()).getTime()));
	}
	
	public static byte[] cipherData(PaddedBufferedBlockCipher cipher, byte[] data) throws Exception {
		byte[] outputBuffer = new byte[cipher.getOutputSize(data.length)];
		
		int length1 = cipher.processBytes(data,  0, data.length, outputBuffer, 0);
		int length2 = cipher.doFinal(outputBuffer, length1);
		
		byte[] result = new byte[length1+length2];
		
		System.arraycopy(outputBuffer, 0, result, 0, result.length);
		
		return result;
	}
	
	public static byte[] encrypt(byte[] plain, CipherParameters ivAndKey) throws Exception {
		PaddedBufferedBlockCipher aes = new PaddedBufferedBlockCipher(
			new CBCBlockCipher(
					new AESEngine()
			)	
		);
		
		aes.init(true, ivAndKey);
		
		return cipherData(aes, plain);
		
	}
	
	public static byte[] decrypt(byte[] cipher, CipherParameters ivAndKey) throws Exception {
		PaddedBufferedBlockCipher aes = new PaddedBufferedBlockCipher(
			new CBCBlockCipher(
					new AESEngine()
			)
		);
		aes.init(false,  ivAndKey);
		
		return cipherData(aes, cipher);
	}
	
	public static void main(String[] args) throws Exception {
//	AsymmetricCipherKeypair includes both private and public keys, but AsymmetricKeyPair includes only public
		Security.addProvider(new BouncyCastleProvider());
		
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(256); //key is 256 bits
		byte[] password = keyGen.generateKey().getEncoded();
		
        KeyGenerator ivGen = KeyGenerator.getInstance("AES");
        ivGen.init(128); //iv is 128 bits
        byte[] iv = ivGen.generateKey().getEncoded();

		CipherParameters ivAndKey = new ParametersWithIV(new KeyParameter(password), iv);
		
		byte[] plainText = "Plain text".getBytes("UTF-8");
		 
		GetTimestamp("Encryption started: ");
		byte[] encryptedMessage = encrypt(plainText, ivAndKey);
		System.out.println(encryptedMessage);
		GetTimestamp("Encryption ended: ");
		 
		GetTimestamp("Decryption started: ");
		byte[] decryptedMessage = decrypt(encryptedMessage, ivAndKey);
		System.out.println(new String(decryptedMessage));
		GetTimestamp("Decryption ended: ");
		
	}

}
