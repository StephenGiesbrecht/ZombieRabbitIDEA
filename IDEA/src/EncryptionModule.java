public class EncryptionModule {

private final int ROUND_KEY_CONSTANT = 3502;
private final int KEY_BIT_LENGTH = 128;

private String key;
private int[] messageSubblocks = new int[4];
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

public void processMessageSubblocks(String message) {
	for (int i = 0; i < message.length() / 4; ++i) {
		messageSubblocks[i] = Integer.parseInt(message.substring(i * 4, (i + 1) * 4), 16);
	}
}

public void test() {
	for (int i = 0; i < roundKeys.length; ++i) {
		System.out.println(roundKeys[i]);
	}
}

public static void main(String args[]) {
	EncryptionModule e = new EncryptionModule("00010002000300040005000600070008");
	e.test();
}
}
