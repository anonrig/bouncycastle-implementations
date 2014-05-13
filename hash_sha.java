import java.security.Security;

import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.ShortenedDigest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.crypto.digests.GOST3411Digest;

public class hash_sha {

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		// TODO Auto-generated method stub
		Security.addProvider(new BouncyCastleProvider());
		
		byte[] trial = "trial".getBytes();
		
		// TODO Auto-generated method stub
		
		//GOST3411Digest examplesha = new GOST3411Digest(); //256-bits
		//SHA1Digest examplesha = new SHA1Digest();
		//SHA256Digest examplesha = new SHA256Digest(); //256-bits
		//SHA384Digest examplesha = new SHA384Digest(); //384-bits
		//SHA512Digest examplesha = new SHA512Digest(); //512-bits
		SHA3Digest examplesha = new SHA3Digest();
		
		examplesha.update(trial, 0, trial.length);
		
		byte[] digested = new byte[examplesha.getDigestSize()];
		examplesha.doFinal(digested, 0);
		
		System.out.println("Input (hex): " + new String(Hex.encode(trial)));
		System.out.println("Output (hex): " + new String(Hex.encode(digested)));
	}

}
