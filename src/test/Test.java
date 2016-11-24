package test;

import hash.SHA1;

public class Test {
	public static void main(String[] args) {
		SHA1 sha = new SHA1();
		String m = "halo";
		byte[] bytes = sha.digest(m.getBytes());
		String S = new String(bytes);
		StringBuilder sb = new StringBuilder();
	    for (byte b : bytes) {
	        sb.append(String.format("%02X ", b));
	    }
	    System.out.println(sb.toString());
	}
}
