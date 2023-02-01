package ActionApplet;

import share.ActionAppletInterface;
import share.AccessControllerAppletInterface;
import javacard.framework.*;

public class ActionAppletClass extends Applet implements ActionAppletInterface {

	/* ---------------- Constants ---------------- */

	private static final byte HW_CLA = (byte) 0x80;

	// Interface
	private AccessControllerAppletInterface AccessControllerIf;

	private ActionAppletClass() {
		AccessControllerIf = null;
	}

	public static void install(byte[] bArray, short bOffset, byte bLength) {
		new ActionAppletClass().register();
	}

	public Shareable getShareableInterfaceObject(AID clientAID, byte parameter) {
		return this;
	}

	public void process(APDU apdu) {

		if (selectingApplet()) {
			return;
		}

		byte[] buffer = apdu.getBuffer();
		byte CLA = (byte) (buffer[ISO7816.OFFSET_CLA] & 0xFF);
		byte INS = (byte) (buffer[ISO7816.OFFSET_INS] & 0xFF);

		if (CLA != HW_CLA) {
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		}
	}

	/**
	 * @brief invoked from the UnLockApplet, invoke the
	 * @param apdu, the APDU buffer
	 */
	public boolean sendACRRequest(APDU apdu) {

		byte[] AccessControllerAID = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x01, 0x00 };
		AID AccessControllerAIDObject = new AID(AccessControllerAID, (short) 0, (byte) AccessControllerAID.length);

		if (AccessControllerIf == null)
			AccessControllerIf = (AccessControllerAppletInterface) JCSystem
					.getAppletShareableInterfaceObject(AccessControllerAIDObject, (byte) 0);
		if (AccessControllerIf == null) // if getting applet crashed
			ISOException.throwIt(ISO7816.SW_APPLET_SELECT_FAILED);

		return AccessControllerIf.getACRAuthorisation(apdu);
	}
}
