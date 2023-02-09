package share;

import javacard.framework.APDU;
import javacard.framework.Shareable;

public interface WalletRUAppletInterface extends Shareable {
	public boolean sendTransactionRequest(APDU apdu);

}
