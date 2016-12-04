import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;

public class EncryptionModule {

private static final int ROUND_KEY_CONSTANT = 0;
private static final int KEY_BIT_LENGTH = 128;
private static final int SUBBLOCK_MAX = 65536;
private static final BigInteger MULTIPLICATION_MODULO = new BigInteger("" + (SUBBLOCK_MAX + 1));

private String key;
private int[] roundKeys = new int[52];

public EncryptionModule(String key) {
	this.key = parseHexKey(key);
	initRoundKeys();
}

private void initRoundKeys() {
	int currBit = 0;
	int offset = 0;
	for (int i = 0; i < 52; ++i) {
		roundKeys[i] = getBits(key, (currBit + offset) % KEY_BIT_LENGTH) ^ ROUND_KEY_CONSTANT;
		if (i % 8 == 7) {
			currBit = 0;
			offset += 25;
		} else {
			currBit = (currBit + 16) % KEY_BIT_LENGTH;
		}
	}
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

	StringBuffer sb = new StringBuffer();
	for (int i = 0; i < 4; ++i) {
		sb.append(Integer.toString(subblocks[i], 16));
	}
	return sb.toString();

}

public String encryptBlock(String block) throws IOException {
	int subblocks[] = processSubblocks(block);
	return computeCipher(subblocks, this.roundKeys);
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

private int multiply(int a, int b) {
	if (a == 0) {
		a = SUBBLOCK_MAX;
	}
	if (b == 0) {
		b = SUBBLOCK_MAX;
	}

	BigInteger result = new BigInteger("" + a).multiply(new BigInteger("" + b));
	result = result.mod(MULTIPLICATION_MODULO);
	return (result.longValue() == SUBBLOCK_MAX ? 0 : result.intValue());
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
	StringBuffer sb = new StringBuffer();
	for (int i = 0; i < Long.numberOfLeadingZeros(message); ++i) {
		sb.append('0');
	}
	sb.append(Long.toUnsignedString(message, 2));
	String binaryBlock = sb.toString();
	for (int i = 0; i < 4; ++i) {
		subblocks[i] = Integer.parseInt(binaryBlock.substring(i * 16, ((i + 1) * 16)), 2);
	}
	return subblocks;
}

public void test() {
	for (int i = 0; i < roundKeys.length; ++i) {
		System.out.println(roundKeys[i]);
	}
}

public static void main(String args[]) throws IOException {
	EncryptionModule e = new EncryptionModule("10002000300040005000600070008");
	String message = "100020003";
	String ciphertext = e.encryptBlock(message);
	System.out.println(ciphertext);
}
}
