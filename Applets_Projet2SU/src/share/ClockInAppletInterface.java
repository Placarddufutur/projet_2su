package share;

import javacard.framework.APDU;
import javacard.framework.Shareable;

public interface ClockInAppletInterface extends Shareable {
	public boolean clockInRequest(APDU apdu);
}
