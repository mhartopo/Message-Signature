package hash;

import java.util.ArrayList;
import java.util.List;

/**
 * A class that works like java.security.MessageDigest, and computes
 * the SHA-1 hash of some data.
 */
public class SHA1 {
	private List<byte[]> inputDataList;
	
	/**
	 * Constructor.
	 */
	public SHA1() {
		this.inputDataList = new ArrayList<byte[]>();
	}

	/*
	 * Bitwise rotate a 32-bit number to the left
	 */
	private static int rol(int num, int cnt) {
		return (num << cnt) | (num >>> (32 - cnt));
	}
	
	/**
	 * Append some data to the message to be hashed.
	 * 
	 * @param data the data to add
	 */
	public void update(byte[] data) {
		inputDataList.add(data);
	}
	
	/**
	 * Return the SHA-1 hash of all of the data added using the
	 * {@link #update(byte[])} method.
	 *  
	 * @return SHA-1 hash of all data added with the update method
	 */
	public byte[] digest() {
		// Combine all chunks into a single array
		int totalNumBytes = 0;
		for (byte[] chunk : inputDataList) {
			totalNumBytes += chunk.length;
		}
		byte[] allData = new byte[totalNumBytes];
		int off = 0;
		for (byte[] chunk : inputDataList) {
			System.arraycopy(chunk, 0, allData, off, chunk.length);
			off += chunk.length;
		}
		
		return digest(allData);
	}

	/**
	 * Take an array of bytes and return its SHA-1 hash as bytes.
	 * Any data added to this object using the {@link #update(byte[])} method
	 * is ignored.
	 * 
	 * @param x the data to hash
	 * @return the SHA-1 hash of the data
	 */
	public byte[] digest(byte[] x) {

		// Convert a string to a sequence of 16-word blocks, stored as an array.
		// Append padding bits and the length, as described in the SHA1 standard

		int[] blks = new int[(((x.length + 8) >> 6) + 1) * 16];
		int i;

		for(i = 0; i < x.length; i++) {
			blks[i >> 2] |= x[i] << (24 - (i % 4) * 8);
		}

		blks[i >> 2] |= 0x80 << (24 - (i % 4) * 8);
		blks[blks.length - 1] = x.length * 8;

		// calculate 160 bit SHA1 hash of the sequence of blocks

		int[] w = new int[80];

		int a =  1732584193;
		int b = -271733879;
		int c = -1732584194;
		int d =  271733878;
		int e = -1009589776;

		for(i = 0; i < blks.length; i += 16) {
			int olda = a;
			int oldb = b;
			int oldc = c;
			int oldd = d;
			int olde = e;

			for(int j = 0; j < 80; j++) {
				w[j] = (j < 16) ? blks[i + j] :
					( rol(w[j-3] ^ w[j-8] ^ w[j-14] ^ w[j-16], 1) );

				int t = rol(a, 5) + e + w[j] +
						( (j < 20) ?  1518500249 + ((b & c) | ((~b) & d))
								: (j < 40) ?  1859775393 + (b ^ c ^ d)
										: (j < 60) ? -1894007588 + ((b & c) | (b & d) | (c & d))
												: -899497514 + (b ^ c ^ d) );
				e = d;
				d = c;
				c = rol(b, 30);
				b = a;
				a = t;
			}

			a = a + olda;
			b = b + oldb;
			c = c + oldc;
			d = d + oldd;
			e = e + olde;
		}

		// Convert result to a byte array
		byte[] digest = new byte[20];
		fill(a, digest, 0);
		fill(b, digest, 4);
		fill(c, digest, 8);
		fill(d, digest, 12);
		fill(e, digest, 16);

		return digest;
	}

	private void fill(int value, byte[] arr, int off) {
		arr[off + 0] = (byte) ((value >> 24) & 0xff);
		arr[off + 1] = (byte) ((value >> 16) & 0xff);
		arr[off + 2] = (byte) ((value >> 8) & 0xff);
		arr[off + 3] = (byte) ((value >> 0) & 0xff);
	}
}
