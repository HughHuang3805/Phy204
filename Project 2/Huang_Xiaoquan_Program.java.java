
import java.io.Console;
import java.math.BigInteger;
import java.security.SecureRandom;

public class RSAEncryption {
	private BigInteger n, d, e;

	private int bitlen = 1024;

	/** Create an instance that can encrypt using someone elses public key. */
	public RSAEncryption(BigInteger newn, BigInteger newe) {
		n = newn;
		e = newe;
	}

	/** Create an instance that can both encrypt and decrypt. */
	public RSAEncryption(int bits) {
		bitlen = bits;
		SecureRandom r = new SecureRandom();
		BigInteger p = new BigInteger(bitlen / 2, 100, r);
		BigInteger q = new BigInteger(bitlen / 2, 100, r);
		n = p.multiply(q);
		BigInteger m = (p.subtract(BigInteger.ONE)).multiply(q
				.subtract(BigInteger.ONE));
		e = new BigInteger("3");
		while (m.gcd(e).intValue() > 1) {
			e = e.add(new BigInteger("2"));
		}
		d = e.modInverse(m);
	}

	/** Encrypt the given plaintext message. */
	public synchronized String encrypt(String message) {
		return (new BigInteger(message.getBytes())).modPow(e, n).toString();
	}

	/** Encrypt the given plaintext message. */
	public synchronized BigInteger encrypt(BigInteger message) {
		return message.modPow(e, n);
	}

	/** Decrypt the given ciphertext message. */
	public synchronized String decrypt(String message) {
		return new String((new BigInteger(message)).modPow(d, n).toByteArray());
	}

	/** Decrypt the given ciphertext message. */
	public synchronized BigInteger decrypt(BigInteger message) {
		return message.modPow(d, n);
	}

	/** Generate a new public and private key set. */
	public synchronized void generateKeys() {
		SecureRandom r = new SecureRandom();
		BigInteger p = new BigInteger(bitlen / 2, 100, r);
		BigInteger q = new BigInteger(bitlen / 2, 100, r);
		n = p.multiply(q);
		BigInteger m = (p.subtract(BigInteger.ONE)).multiply(q
				.subtract(BigInteger.ONE));
		e = new BigInteger("3");
		while (m.gcd(e).intValue() > 1) {
			e = e.add(new BigInteger("2"));
		}
		d = e.modInverse(m);
	}

	/** Return the modulus. */
	public synchronized BigInteger getN() {
		return n;
	}

	/** Return the public key. */
	public synchronized BigInteger getE() {
		return e;
	}

	public static void main(String[] args) {
		RSAEncryption rsa = new RSAEncryption(1024);
		Console console = System.console();

		
		String text1 = console.readLine("Enter a string to encypt: ");
		System.out.println("Plaintext: " + text1);
		BigInteger plaintext = new BigInteger(text1.getBytes());

		BigInteger ciphertext = rsa.encrypt(plaintext);
		System.out.println("Ciphertext in bytes: " + ciphertext);
		plaintext = rsa.decrypt(ciphertext);

		String text2 = new String(plaintext.toByteArray());
		System.out.println("Plaintext after decrypted: " + text2);
	}
	
}
