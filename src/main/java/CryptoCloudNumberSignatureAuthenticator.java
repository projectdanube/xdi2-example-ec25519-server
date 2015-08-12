import xdi2.core.features.signatures.Signature;
import xdi2.core.syntax.CloudNumber;
import xdi2.messaging.Message;
import xdi2.messaging.target.interceptor.impl.authentication.signature.AbstractSignatureAuthenticator;
import xdi2.messaging.target.interceptor.impl.authentication.signature.SignatureAuthenticator;

public class CryptoCloudNumberSignatureAuthenticator extends AbstractSignatureAuthenticator implements SignatureAuthenticator {

	@Override
	public boolean authenticate(Message message, Signature<?, ?> signature) {

		CloudNumber cloudNumber = CloudNumber.fromXDIAddress(message.getSenderXDIAddress());

		byte[] key = CryptoCloudNumberPublicKey.pub(cloudNumber);

		try {
			Crypto.validate(signature, key);
		} catch (Exception e) {
			e.printStackTrace(System.err);
			return false;
		}

		return true;
	}
}
