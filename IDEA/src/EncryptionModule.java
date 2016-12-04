import java.math.BigInteger;

public class EncryptionModule {

private static final int ROUND_KEY_CONSTANT = 3502;
private static final int KEY_BIT_LENGTH = 128;
private static final int SUBBLOCK_MAX = 65536;
private final static BigInteger MULTIPLICATION_MOD = new BigInteger("" + (SUBBLOCK_MAX + 1));

private int[] encKeys = new int[52];
private int[] decKeys = new int[52];

public EncryptionModule(String key) {
	initRoundKeys(parseHexKey(key));
}

/*
 * Generates the 52 round keys from the given secret key. Converting to a
 * numeric value drops leading 0s so a string repsresentation is used. Because
 * of this, actually rotating the key is impossible, so it is simulated with an
 * offset. Also calculates the decryption keys by taking inverses of the
 * encryption keys.
 */
private void initRoundKeys(String key) {
	int currBit = 0;
	int offset = 0;
	for (int i = 0; i < 52; ++i) {
		encKeys[i] = extractBits(key, (currBit + offset) % KEY_BIT_LENGTH) ^ ROUND_KEY_CONSTANT;
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

public String decrypt(String ciphertext) {
	StringBuffer result = new StringBuffer();
	StringBuffer nextBlock = new StringBuffer();
	int currIndex = 0;
	int messageLength = ciphertext.length();
	int requiredPadding = (16 - (messageLength % 16)) % 16;

	for (int i = 0; i < requiredPadding; ++i) {
		nextBlock.append('0');
	}
	if (requiredPadding != 0) {
		nextBlock.append(ciphertext.substring(0, messageLength % 16));
		currIndex += messageLength % 16;
		result.append(decryptBlock(nextBlock.toString()));
	}
	while (currIndex < messageLength) {
		nextBlock = new StringBuffer(ciphertext.substring(currIndex, currIndex + 16));
		currIndex += 16;
		result.append(decryptBlock(nextBlock.toString()));
	}

	int resultLength = result.length();
	int paddingChars = Integer.parseInt("" + result.charAt(resultLength - 1), 16);
	result.delete(resultLength - paddingChars - 1, resultLength);

	return result.toString();
}

/**
 * Decrypts a single block given the hexadecimal representation of the
 * ciphertext.
 *
 *  @param block The hexadecimal representation of the block to decrypt
 *  @return The hexadecimal representation of the plaintext, as a {@link String}
 */
public String decryptBlock(String block) {
	int subblocks[] = processSubblocks(block);
	return computeCipher(subblocks, this.decKeys);
}

/*
 * Computes the actual cipher. This same process is used for either encryption
 * or decryption depending on the set of round keys used
 */
private String computeCipher(int[] subblocks, int[] keys) {
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
	}

	subblocks[0] = multiply(subblocks[0], keys[48]);
	subblocks[1] = multiply(subblocks[1], keys[49]);
	subblocks[2] = (subblocks[2] + keys[50]) % SUBBLOCK_MAX;
	subblocks[3] = (subblocks[3] + keys[51]) % SUBBLOCK_MAX;

	return reconstructBlock(subblocks);
}

public String encrypt(String message) {
	StringBuffer result = new StringBuffer();
	StringBuffer nextBlock;
	int currIndex = 0;
	int messageLength = message.length();

	while (currIndex <= messageLength) {
		int availableLength = messageLength - currIndex;
		nextBlock = new StringBuffer();

		if (availableLength == 0) {
			currIndex++;
			nextBlock.append("ffffffffffffffff");

		} else if (availableLength < 16) {
			String hexChar = Integer.toHexString(16 - availableLength);
			nextBlock.append(message.substring(currIndex));
			for (int i = 0; i < 16 - availableLength; ++i) {
				nextBlock.append(hexChar);
			}

		} else {
			nextBlock.append(message.substring(currIndex, currIndex + 16));
		}
		currIndex += 16;
		result.append(encryptBlock(nextBlock.toString()));
	}
	return result.toString();

}

/**
 * Encrypts a single block given the hexadecimal representation of the plaintext
 *
 * @param block The hexadecimal representation of the block to encrypt
 * @return The hexadecimal representation of the ciphertext, as a [@link String}
 */
public String encryptBlock(String block) {
	int subblocks[] = processSubblocks(block);
	return computeCipher(subblocks, this.encKeys);
}

/*
 * Extracts a single 16-bit subkey from the given key, starting from the bit at
 * the given index. The extracted bits are combined into a numeric
 * representation
 */
private int extractBits(String key, int startBit) {
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

/*
 * Calculates the multiplicative inverse of the given number modulo
 * (SUBBLOCK_MAX + 1). As in the multiplication algorithm, 0 as input is treated
 * as SUBBLOCK_MAX and SUBBLOCK_MAX as output is treated as 0
 */
private int getMultiplicativeInverse(int val) {
	BigInteger bigKey = (new BigInteger("" + (val == 0 ? SUBBLOCK_MAX : val)));
	int result = bigKey.modInverse(MULTIPLICATION_MOD).intValue();
	return (result == SUBBLOCK_MAX ? 0 : result);
}

/*
 * Multiply two numbers modulo (SUBBLOCK_MAX + 1). A 0 as input is treated as
 * SUBBLOCK_MAX and SUBBLOCK_MAX as output is treated as 0
 */
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

/*
 * Parse a hexadecimal representation of a 128-bit key and return a binary
 * representation. String representations are used instead of numeric to
 * preserve leading 0s
 */
private String parseHexKey(String hexKey) {
	StringBuffer sb = new StringBuffer();
	BigInteger key = new BigInteger(hexKey, 16);
	for (int i = 0; i < KEY_BIT_LENGTH - key.bitLength(); ++i) {
		sb.append('0');
	}
	sb.append(key.toString(2));
	return sb.toString();
}

/*
 * Split a 64-bit block into four 16-bit subblocks for processing
 */

private int[] processSubblocks(String block) {
	long message = Long.parseUnsignedLong(block, 16);
	int subblocks[] = new int[4];
	for (int i = 3; i >= 0; --i) {
		subblocks[i] = Short.toUnsignedInt((short) (message >>> ((3 - i) * 16)));
	}
	return subblocks;
}

/*
 * Reconstruct a 64-bit block from four 16-bit subblocks
 */
private String reconstructBlock(int[] subblocks) {
	long block = 0;
	for (int i = 3; i >= 0; --i) {
		block += (long) (subblocks[i]) << ((3 - i) * 16);
	}
	StringBuffer sb = new StringBuffer("");
	for (int i = 0; i < Long.numberOfLeadingZeros(block) / 4; ++i) {
		sb.append('0');
	}
	sb.append(Long.toHexString(block));
	return sb.toString();
}

public static void main(String args[]) {
	EncryptionModule e = new EncryptionModule("10002000300040005000600070008");
	String message = "0000000100020003";
	String ciphertext = e.encrypt(message);
	System.out.println(ciphertext);

	String plaintext = e.decrypt(ciphertext);
	System.out.println(plaintext);
}
}
