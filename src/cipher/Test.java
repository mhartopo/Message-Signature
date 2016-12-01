package cipher;
import java.nio.charset.StandardCharsets;

import utils.HexUtil;
public class Test {
	public static void main(String[] args) {
		MBCipher mc = new MBCipher();
		String text = "halo, besok adaa apa ya saya juga tidak tahu itu haha";
		String key = "informatikasteii";
		byte[] btext = text.getBytes(StandardCharsets.UTF_8);
		
		byte[] bkey = key.getBytes();
		byte[] cipher = mc.encrypt(btext, bkey);
		System.out.println(HexUtil.bytesHex(cipher));
		byte[] plain = mc.decrypt(cipher, bkey);
		String decrypted = new String(plain, StandardCharsets.UTF_8);
		System.out.println(decrypted);
		
	}
	
}
