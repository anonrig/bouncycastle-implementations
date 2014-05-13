import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;


public class hash_md5 {

	/**
	 * @param args
	 * @throws NoSuchAlgorithmException 
	 * @throws UnsupportedEncodingException 
	 */
	public static void main(String[] args) throws NoSuchAlgorithmException, UnsupportedEncodingException {

		Security.addProvider(new BouncyCastleProvider());
		
		byte[] trial = "trial".getBytes();
		
		
		
		// TODO Auto-generated method stub
		MD5Digest examplemd5 = new MD5Digest();
		examplemd5.update(trial, 0, trial.length);
		
		byte[] digested = new byte[examplemd5.getDigestSize()];
		examplemd5.doFinal(digested, 0);
		
		System.out.println("Input (hex): " + new String(Hex.encode(trial)));
		System.out.println("Output (hex): " + new String(Hex.encode(digested)));
		
	}

}
