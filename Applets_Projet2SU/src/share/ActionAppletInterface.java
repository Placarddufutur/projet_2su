package share;
import javacard.framework.APDU;
import javacard.framework.Shareable;

public interface ActionAppletInterface extends Shareable {
	public boolean sendACRRequest(APDU apdu);
}
