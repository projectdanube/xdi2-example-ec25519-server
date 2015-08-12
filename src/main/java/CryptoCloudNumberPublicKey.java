import java.util.Arrays;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import xdi2.core.syntax.CloudNumber;

public class CryptoCloudNumberPublicKey {

	private static final Logger log = LoggerFactory.getLogger(CryptoCloudNumberPublicKey.class);

	static byte[] pub(CloudNumber cloudNumber) {

		if (! cloudNumber.toString().startsWith("=!:publickey-curve25519-base58-check:")) throw new IllegalArgumentException("Not a crypto cloud number.");

		String string1 = cloudNumber.toString().substring("=!:publickey-curve25519-base58-check:".length());
		log.info("str: " + string1);
		byte[] bytes2 = null;
		bytes2 = Base58.decode(string1);

		// todo: check sha checksum

		return Arrays.copyOfRange(bytes2, 1, bytes2.length - 4);
	}
}
