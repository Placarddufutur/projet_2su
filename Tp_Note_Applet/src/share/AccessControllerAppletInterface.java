package share;

import javacard.framework.APDU;
import javacard.framework.Shareable;

public interface AccessControllerAppletInterface extends Shareable {
	public boolean verifyPassword(APDU apdu);
	public boolean getACRAuthorisation(APDU apdu);
	public boolean verifyMasterPin(APDU apdu);
}
