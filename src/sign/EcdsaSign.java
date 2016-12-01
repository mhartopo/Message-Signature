package sign;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;
import java.sql.Timestamp;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.util.encoders.Hex;

import hash.SHA1;
import utils.HexUtil;

public class EcdsaSign {
	private KeyPair keyPair;
    private ECCurve curve;
    private ECParameterSpec spec;
    private KeyPairGenerator g;
    private KeyFactory f;
    
    public EcdsaSign() {
    	Security.addProvider(new BouncyCastleProvider());
    }
    
	public static void GetTimestamp(String info){
		System.out.println(info + new Timestamp((new Date()).getTime()));
	}
	
	public byte[] generateSignature(String plaintext) throws SignatureException, UnsupportedEncodingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException{
		SHA1 sha = new SHA1();
		Signature ecdsaSign = Signature.getInstance("SHA1withECDSA", "BC");
		ecdsaSign.initSign(keyPair.getPrivate());
		ecdsaSign.update(plaintext.getBytes("UTF-8"));
		byte[] signature = ecdsaSign.sign();
		return signature;
	}
	
	public String generateSignatureHex(String plaintext) {
		String res = "";
		try {
			res  = HexUtil.bytesHex(generateSignature(plaintext));
		} catch (InvalidKeyException | SignatureException | UnsupportedEncodingException | NoSuchAlgorithmException
				| NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return res;
	}
	
	public boolean validateSignatureHex(String plaintext, String hexpub, String hexSign) {
		byte[] bpub = new BigInteger(hexpub,16).toByteArray();
		byte[] sign = new BigInteger(hexSign,16).toByteArray();
		boolean res = false;
		try {
			res = validateSignature(plaintext, bpub, sign);
		} catch (InvalidKeyException | SignatureException | UnsupportedEncodingException | NoSuchAlgorithmException
				| NoSuchProviderException | InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return res;
	}
	
	public boolean validateSignature(String plaintext, byte[] publicKey, byte[] signature) throws SignatureException, InvalidKeyException, UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException{
		SHA1 sha = new SHA1();
		Signature ecdsaVerify = Signature.getInstance("SHA1withECDSA", "BC");
		X509EncodedKeySpec pub_format = new  X509EncodedKeySpec(publicKey);
		PublicKey pub = f.generatePublic(pub_format);
		ecdsaVerify.initVerify(pub);
		ecdsaVerify.update(plaintext.getBytes("UTF-8"));
		return ecdsaVerify.verify(signature);
	}
	
	public void init() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException{
		curve = new ECCurve.Fp(
                new BigInteger("883423532389192164791648750360308885314476597252960362792450860609699839"), // q
                new BigInteger("7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc", 16), // a
                new BigInteger("6b016c3bdcf18941d0d654921475ca71a9db2fb27d1d37796185c2942c0a", 16)); // b
    	spec = new ECParameterSpec(
                curve,
                curve.decodePoint(Hex.decode("020ffa963cdca8816ccc33b8642bedf905c3d358573d3f27fbbd3b3cb9aaaf")), // G
                new BigInteger("883423532389192164791648750360308884807550341691627752275345424702807307")); // n
    	g = KeyPairGenerator.getInstance("ECDSA", "BC");
    	g.initialize(spec, new SecureRandom());
    	f = KeyFactory.getInstance("ECDSA", "BC");
    	keyPair = g.generateKeyPair();
	}
	
	public void init(String hexpub, String hexpriv) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeySpecException {
		curve = new ECCurve.Fp(
                new BigInteger("883423532389192164791648750360308885314476597252960362792450860609699839"), // q
                new BigInteger("7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc", 16), // a
                new BigInteger("6b016c3bdcf18941d0d654921475ca71a9db2fb27d1d37796185c2942c0a", 16)); // b
    	spec = new ECParameterSpec(
                curve,
                curve.decodePoint(Hex.decode("020ffa963cdca8816ccc33b8642bedf905c3d358573d3f27fbbd3b3cb9aaaf")), // G
                new BigInteger("883423532389192164791648750360308884807550341691627752275345424702807307")); // n
    	g = KeyPairGenerator.getInstance("ECDSA", "BC");
    	g.initialize(spec, new SecureRandom());
    	f = KeyFactory.getInstance("ECDSA", "BC");
    	
    	byte[] bpriv = new BigInteger(hexpriv,16).toByteArray();
    	byte[] bpub = new BigInteger(hexpub,16).toByteArray();
    	X509EncodedKeySpec pub_format = new  X509EncodedKeySpec(bpub);
    	PKCS8EncodedKeySpec priv_format = new PKCS8EncodedKeySpec(bpriv);
    	
    	PublicKey pub = f.generatePublic(pub_format);
    	PrivateKey priv = f.generatePrivate(priv_format);
    	keyPair = new KeyPair(pub, priv);
	}
	
	public byte[] getPublicKey() {
		return keyPair.getPublic().getEncoded();
	}
	
	public byte[] getPrivateKey() {
		return keyPair.getPrivate().getEncoded();
	}
	
	public String getPublicKeyHex() {
		return HexUtil.bytesHex(getPublicKey());
	}
	
	public String getPrivateKeyHex() {
		return HexUtil.bytesHex(getPrivateKey());
	}
	
	public MessageSign generateMsgWSign(String message) {
		return new MessageSign(message, generateSignatureHex(message));
	}
	
	public boolean validate(MessageSign m, String hexpub) {
		return this.validateSignatureHex(m.getMessage(), hexpub, m.getMessage());
	}
	
	public static void main(String[] args) throws Exception {
		EcdsaSign s = new EcdsaSign();
		//generate new key pair
		s.init();
		//use saved keypait
		//s.init(publickey, privateKey );
		
		String m = "halo halo bandung, ibu kota periangan";
		String m2 = "halo halo bandung, ibu kota perianga";
		String sign = s.generateSignatureHex(m);
		System.out.println(s.validateSignatureHex(m2, s.getPublicKeyHex(), sign));
		System.out.println(s.validateSignatureHex(m, s.getPublicKeyHex(), sign));
	}

}
