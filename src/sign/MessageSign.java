package sign;

import java.security.Security;

import org.spongycastle.crypto.digests.SHA1Digest;
import org.spongycastle.jcajce.provider.digest.SHA1;
import org.spongycastle.jce.provider.BouncyCastleProvider;

public class MessageSign {
	private String message;
	private String sign;
	
	public MessageSign(String m_message, String m_sign) {
		message = m_message;
		sign = m_sign;
	}
	
	public String getMessage() {
		return message;
	}
	
	public void setMessage(String message) {
		this.message = message;
	}
	
	public String getSign() {
		return sign;
	}
	
	public void setSign(String sign) {
		this.sign = sign;
	}
	
	@Override
	public String toString() {
		String res = message + "\n" + "<ds>" + sign + "</ds>";
		return res;
	}
	
	public static void main(String[] args) {
		
	}
}
