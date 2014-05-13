import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;
import java.util.Date;
import java.sql.Timestamp;

import javax.crypto.KeyAgreement;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;

public class trial {
	
	public static void GetTimestamp(String info){
		System.out.println(info + new Timestamp((new Date()).getTime()));
	}
	
	public static boolean GenerateAgreement() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException {
		ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("B-571");

		KeyPairGenerator g = KeyPairGenerator.getInstance("ECDH", "BC");

		g.initialize(ecSpec, new SecureRandom());

		KeyPair aKeyPair = g.generateKeyPair();
		
			KeyAgreement aKeyAgree = KeyAgreement.getInstance("ECDH", "BC");
		
			aKeyAgree.init(aKeyPair.getPrivate());
		
		KeyPair bKeyPair = g.generateKeyPair();
		 
        	KeyAgreement bKeyAgree = KeyAgreement.getInstance("ECDH", "BC");

        	bKeyAgree.init(bKeyPair.getPrivate());

        //
        // agreement
        //
        aKeyAgree.doPhase(bKeyPair.getPublic(), true);
        bKeyAgree.doPhase(aKeyPair.getPublic(), true);
        
        byte[] aSecret = aKeyAgree.generateSecret();
        byte[] bSecret = bKeyAgree.generateSecret();
        
//        System.out.println(Arrays.toString(aSecret));
//        System.out.println(Arrays.toString(bSecret));
        
        return MessageDigest.isEqual(aSecret, bSecret);
	}
	
	public static void main(String[] args) throws Exception {

		Security.addProvider(new BouncyCastleProvider());
		
		GetTimestamp("Key Generation started: ");
		System.out.println(GenerateAgreement());
//		System.out.println(keys.getPublic().toString());
//		System.out.println(keys.getPrivate().toString());
		GetTimestamp("Key Generation ended: ");
		
		
	}

}
