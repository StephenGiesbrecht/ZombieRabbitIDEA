public class EncryptionModule {

private final int ROUND_KEY_CONSTANT = 0;
private final int KEY_BIT_LENGTH = 128;
private final int SUBBLOCK_MAX = 65536;

private String key;
private int[] roundKeys = new int[52];

public EncryptionModule(String key) {
	this.key = parseHexKey(key);
	System.out.println(this.key);
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
	}

	subblocks[0] = multiply(subblocks[0], keys[48]);
	subblocks[1] = multiply(subblocks[1], keys[49]);
	subblocks[2] = (subblocks[2] + keys[50]) % SUBBLOCK_MAX;
	subblocks[3] = (subblocks[3] + keys[51] % SUBBLOCK_MAX);

	StringBuffer sb = new StringBuffer();
	for (int i = 0; i < 4; ++i) {
		sb.append(Integer.toString(subblocks[i], 16));
	}
	return sb.toString();

}

public String encryptBlock(String block) {
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

	long result = (a * b) % (SUBBLOCK_MAX + 1);
	return (result == SUBBLOCK_MAX ? 0 : (int) result);
}

private String parseHexKey(String hexKey) {
	StringBuffer sb = new StringBuffer();
	for (int i = 0; i < hexKey.length(); i += 2) {
		byte b = Byte.parseByte(hexKey.substring(i, i + 2), 16);
		for (int j = 128; j >= 1; j = j / 2) {
			if (b >= j) {
				sb.append('1');
				b -= j;
			} else {
				sb.append('0');
			}
		}
	}
	return sb.toString();
}

private int[] processSubblocks(String block) {
	int messageSubblocks[] = new int[4];
	for (int i = 0; i < block.length() / 4; ++i) {
		messageSubblocks[i] = Integer.parseInt(block.substring(i * 4, (i + 1) * 4), 16);
	}
	return messageSubblocks;
}

public void test() {
	for (int i = 0; i < roundKeys.length; ++i) {
		System.out.println(roundKeys[i]);
	}
}

public static void main(String args[]) {
	EncryptionModule e = new EncryptionModule("00010002000300040005000600070008");
	String message = "0000000100020003";
	String ciphertext = e.encryptBlock(message);
	System.out.println(ciphertext);
	System.out.println(Integer.parseInt(ciphertext, 16));
}
}
