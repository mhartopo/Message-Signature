package sign;

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
}
