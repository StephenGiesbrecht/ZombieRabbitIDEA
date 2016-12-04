import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;

public class EncryptionModule {

private static final int ROUND_KEY_CONSTANT = 0;
private static final int KEY_BIT_LENGTH = 128;
private static final int SUBBLOCK_MAX = 65536;
private final static BigInteger MULTIPLICATION_MOD = new BigInteger("" + (SUBBLOCK_MAX + 1));

private int[] encKeys = new int[52];
private int[] decKeys = new int[52];

public EncryptionModule(String key) {
	initRoundKeys(parseHexKey(key));
}

private void initRoundKeys(String key) {
	int currBit = 0;
	int offset = 0;
	for (int i = 0; i < 52; ++i) {
		encKeys[i] = getBits(key, (currBit + offset) % KEY_BIT_LENGTH) ^ ROUND_KEY_CONSTANT;
		if (i % 8 == 7) {
			currBit = 0;
			offset += 25;
		} else {
			currBit = (currBit + 16) % KEY_BIT_LENGTH;
		}
	}

	for (int i = 0; i < 48; i += 6) {
		decKeys[i] = getMultiplicativeInverse(encKeys[48 - i]);
		decKeys[i + 1] = getMultiplicativeInverse(encKeys[49 - i]);

		decKeys[i + 2] = SUBBLOCK_MAX - encKeys[50 - i];
		decKeys[i + 3] = SUBBLOCK_MAX - encKeys[51 - i];

		decKeys[i + 4] = encKeys[46 - i];
		decKeys[i + 5] = encKeys[47 - i];
	}

	decKeys[48] = getMultiplicativeInverse(encKeys[0]);
	decKeys[49] = getMultiplicativeInverse(encKeys[1]);

	decKeys[50] = SUBBLOCK_MAX - encKeys[2];
	decKeys[51] = SUBBLOCK_MAX - encKeys[3];

}

public String decrpyptBlock(String block) throws IOException {
	int subblocks[] = processSubblocks(block);
	return computeCipher(subblocks, this.decKeys);
}

private String computeCipher(int[] subblocks, int[] keys) throws IOException {
	FileWriter fw = new FileWriter("out.txt");
	int temp1, temp2, temp3;
	for (int i = 0; i < 8; ++i) {
		subblocks[0] = multiply(subblocks[0], keys[i * 6]);
		subblocks[1] = multiply(subblocks[1], keys[i * 6 + 1]);
		subblocks[2] = (subblocks[2] + keys[i * 6 + 2]) % SUBBLOCK_MAX;
		subblocks[3] = (subblocks[3] + keys[i * 6 + 3]) % SUBBLOCK_MAX;

		temp1 = multiply(subblocks[0] ^ subblocks[2], keys[i * 6 + 4]);
		temp2 = ((subblocks[1] ^ subblocks[3]) + temp1) % SUBBLOCK_MAX;
		temp2 = multiply(temp2, keys[i * 6 + 5]);
		temp1 = (temp1 + temp2) % SUBBLOCK_MAX;

		temp3 = subblocks[2] ^ temp2;
		subblocks[2] = subblocks[0] ^ temp2;
		subblocks[0] = temp3;

		temp3 = subblocks[3] ^ temp1;
		subblocks[3] = subblocks[1] ^ temp1;
		subblocks[1] = temp3;

		StringBuffer sb = new StringBuffer();
		for (int ctr = 0; ctr < 6; ++ctr) {
			sb.append(keys[i * 6 + ctr]).append(", ");
		}
		fw.write(sb.toString() + "\n");
		fw.write(subblocks[0] + ", " + subblocks[1] + ", " + subblocks[2] + ", " + subblocks[3] + "\n\n");
	}

	subblocks[0] = multiply(subblocks[0], keys[48]);
	subblocks[1] = multiply(subblocks[1], keys[49]);
	subblocks[2] = (subblocks[2] + keys[50]) % SUBBLOCK_MAX;
	subblocks[3] = (subblocks[3] + keys[51]) % SUBBLOCK_MAX;

	fw.write(subblocks[0] + ", " + subblocks[1] + ", " + subblocks[2] + ", " + subblocks[3]);
	fw.close();

	return reconstructBlock(subblocks);
}

public String encryptBlock(String block) throws IOException {
	int subblocks[] = processSubblocks(block);
	return computeCipher(subblocks, this.encKeys);
}

private int getBits(String key, int startBit) {
	int result = 0;
	int currBit = startBit;
	for (int i = 15; i >= 0; --i) {
		if (key.charAt(currBit) == '1') {
			result += Math.pow(2, i);
		}
		currBit = (currBit + 1) % KEY_BIT_LENGTH;
	}
	return result;
}

private int getMultiplicativeInverse(int val) {
	BigInteger bigKey = (new BigInteger("" + (val == 0 ? SUBBLOCK_MAX : val)));
	int result = bigKey.modInverse(MULTIPLICATION_MOD).intValue();
	return (result == SUBBLOCK_MAX ? 0 : result);
}

private int multiply(int a, int b) {
	if (a == 0) {
		a = SUBBLOCK_MAX;
	}
	if (b == 0) {
		b = SUBBLOCK_MAX;
	}

	long result = (long) (a) * b % (SUBBLOCK_MAX + 1);
	return result == SUBBLOCK_MAX ? 0 : (int) (result);
}

private String parseHexKey(String hexKey) {
	StringBuffer sb = new StringBuffer();
	BigInteger key = new BigInteger(hexKey, 16);
	for (int i = 0; i < KEY_BIT_LENGTH - key.bitLength(); ++i) {
		sb.append('0');
	}
	sb.append(key.toString(2));
	return sb.toString();
}

private int[] processSubblocks(String block) {
	long message = Long.parseUnsignedLong(block, 16);
	int subblocks[] = new int[4];
	for (int i = 3; i >= 0; --i) {
		subblocks[i] = (short) (message >>> ((3 - i) * 16));
	}
	return subblocks;
}

private String reconstructBlock(int[] subblocks) {
	long block = 0;
	for (int i = 3; i >= 0; --i) {
		block += (long) (subblocks[i]) << ((3 - i) * 16);
	}
	return Long.toHexString(block);
}

public void test() {
	for (int i = 0; i < encKeys.length; ++i) {
		System.out.println(encKeys[i]);
	}
}

public static void main(String args[]) throws IOException {
	EncryptionModule e = new EncryptionModule("10002000300040005000600070008");
	String message = "100020003";
	String ciphertext = e.encryptBlock(message);
	System.out.println(ciphertext);

	String plaintext = e.decrpyptBlock(ciphertext);
	System.out.println(plaintext);
}
}
