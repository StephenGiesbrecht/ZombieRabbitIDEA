import java.math.BigInteger;

public class EncryptionModule {

private static final int ROUND_KEY_CONSTANT = 3502;
private static final int KEY_BIT_LENGTH = 128;
private static final int SUBBLOCK_MAX = 65536;
private final static BigInteger MULTIPLICATION_MOD = new BigInteger("" + (SUBBLOCK_MAX + 1));
private static final long IV = 0x13572468;

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

/** Decrypt the given message
 *
 * @param message The hexadecimal representation of the ciphertext to decrypt
 * @return The hexadecimal representation of the plaintext, as a {@link String}
 * @throws IllegalArgumentException If the ciphertext does not evenly divide into blocks of 16 characters
 */
public String decrypt(String ciphertext) {
	StringBuffer result = new StringBuffer();
	StringBuffer blockSB = new StringBuffer();
	int currIndex = 0;
	long prevBlock = IV;
	long currBlock;
	int messageLength = ciphertext.length();

	if (messageLength % 16 != 0)
		throw new IllegalArgumentException("Ciphertext is not evenly divisible into blocks! It must be a multiple of 16 characters");

	while (currIndex < messageLength) {
		blockSB = new StringBuffer(ciphertext.substring(currIndex, currIndex + 16));
		currIndex += 16;

		// Take each block, decrypt, and XOR with previous ciphertext block for
		// CBC mode of operation
		currBlock = Long.parseUnsignedLong(blockSB.toString(), 16);
		result.append(getHexOutputBlock(decryptBlock(currBlock) ^ prevBlock));
		prevBlock = currBlock;
	}

	// Remove padding bytes from the end of the message
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
private long decryptBlock(long block) {
	int subblocks[] = processSubblocks(block);
	return computeCipher(subblocks, this.decKeys);
}

/*
 * Computes the actual cipher. This same process is used for either encryption
 * or decryption depending on the set of round keys used
 */
private long computeCipher(int[] subblocks, int[] keys) {
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
	}

	subblocks[0] = multiply(subblocks[0], keys[48]);
	subblocks[1] = multiply(subblocks[1], keys[49]);
	subblocks[2] = (subblocks[2] + keys[50]) % SUBBLOCK_MAX;
	subblocks[3] = (subblocks[3] + keys[51]) % SUBBLOCK_MAX;

	return reconstructBlock(subblocks);
}

/** Encrypt the given message
 *
 * @param message The hexadecimal representation of the plaintext to encrypt
 * @return The hexadecimal representation of the ciphertext, as a {@link String}
 */
public String encrypt(String message) {
	StringBuffer result = new StringBuffer();
	StringBuffer blockSB;
	int currIndex = 0;
	int messageLength = message.length();
	long prevBlock = IV;

	while (currIndex <= messageLength) {
		int availableLength = messageLength - currIndex;
		blockSB = new StringBuffer();

		// Apply extra block of padding if message evenly splits into blocks
		// This guarantees there will always be some padding so decryption
		// can identify padding bits accurately
		if (availableLength == 0) {
			currIndex++;
			blockSB.append("ffffffffffffffff");

			// Pad partial block. Padding consists of of N half-bytes, each with
			// value N-1,
			// such that the total length of the block becomes 8 bytes
		} else if (availableLength < 16) {
			String hexChar = Integer.toHexString(15 - availableLength);
			blockSB.append(message.substring(currIndex));
			for (int i = 0; i < 16 - availableLength; ++i) {
				blockSB.append(hexChar);
			}

			// Directly extract blocks that need no padding
		} else {
			blockSB.append(message.substring(currIndex, currIndex + 16));
		}
		currIndex += 16;

		// Encrypt block and XOR with previous block for CBC mode of operation
		prevBlock = encryptBlock(Long.parseUnsignedLong(blockSB.toString(), 16) ^ prevBlock);
		result.append(getHexOutputBlock(prevBlock));
	}
	return result.toString();

}

/**
 * Encrypts a single block given the hexadecimal representation of the plaintext
 *
 * @param block The hexadecimal representation of the block to encrypt
 * @return The hexadecimal representation of the ciphertext, as a [@link String}
 */
private long encryptBlock(long block) {
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
 * Converts a binary block into a hexidecimal string for output. Keeps any
 * leading 0s as those are important for middle blocks in a longer message
 */
private String getHexOutputBlock(long block) {
	StringBuffer sb = new StringBuffer("");
	for (int i = 0; i < Long.numberOfLeadingZeros(block) / 4; ++i) {
		sb.append('0');
	}
	sb.append(Long.toHexString(block));
	return sb.toString();
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

private int[] processSubblocks(long block) {
	int subblocks[] = new int[4];
	for (int i = 3; i >= 0; --i) {
		subblocks[i] = Short.toUnsignedInt((short) (block >>> ((3 - i) * 16)));
	}
	return subblocks;
}

/*
 * Reconstruct a 64-bit block from four 16-bit subblocks
 */
private long reconstructBlock(int[] subblocks) {
	long block = 0;
	for (int i = 3; i >= 0; --i) {
		block += (long) (subblocks[i]) << ((3 - i) * 16);
	}
	return block;
}

public static void main(String args[]) {
	EncryptionModule e = new EncryptionModule("fff02ac0a00040005400603070008");
	String message = "23fef001d26090b03a100";
	String ciphertext = e.encrypt(message);
	System.out.println(ciphertext);

	String plaintext = e.decrypt(ciphertext);
	System.out.println(plaintext);
}
}
