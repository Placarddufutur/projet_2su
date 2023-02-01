package UnLockApplet;

import share.AccessControllerAppletInterface;
import share.ActionAppletInterface;
import javacard.framework.*;

public class UnLockAppletClass extends Applet {

	/* ---------------- Constants ---------------- */

	final static byte CP_CLA = (byte) 0x80;

	// INS Codes
	private static final byte SEND_PASSWORD_INS = (byte) 0x02;
	private static final byte VERIFY_USER_PIN_INS = (byte) 0x20;
	private static final byte AUTHORIZATION_ROOM_INS = (byte) 0x04;

	// Interface
	private AccessControllerAppletInterface AccessControllerIf;
	private ActionAppletInterface ActionIf;

	// PIN Handling
	private static final byte USER_PIN_PARAM = (byte) 0x82;
	private static final byte MAX_PIN_LENGTH = 0x05;
	public static final byte MAX_PASSWD_LENGTH = 0x0a;
	final static byte PIN_TRY_LIMIT = (byte) 0x64;
	final static byte MAX_PIN_SIZE = (byte) 0x05;
	OwnerPIN pin;

	// Auth consts
	private boolean PIN_AUTHENTICATION_SUCCESS = false;
	private boolean PASSWD_AUTHENTICATION_SUCCESS = false;
	private boolean ROOM_AUTHORIZATION_SUCESS = false;

	// Auth verification errors
	final static short SW_VERIFICATION_FAILED = 0x6300;
	final static short SW_WRONG_PASSWORD = 0x6301;
	final static short SW_UNAUTHORIZED_ACCESS = 0x6303;

	// Room consts
	final static byte[] UNLOCK_DOOR_CODE = { 0x64, 0x44 };

	/* instance variables declaration */
	private UnLockAppletClass(byte[] bArray, short bOffset, byte bLength) {

		AccessControllerIf = null;
		ActionIf = null;

		// It is good programming practice to allocate
		// all the memory that an applet needs during
		// its lifetime inside the constructor
		pin = new OwnerPIN(PIN_TRY_LIMIT, MAX_PIN_SIZE);
		byte iLen = bArray[bOffset]; // aid length
		bOffset = (short) (bOffset + iLen + 1);
		byte cLen = bArray[bOffset]; // info length
		bOffset = (short) (bOffset + cLen + 1);
		byte aLen = bArray[bOffset]; // applet data length

		// The installation parameters contain the PIN initialization value
		pin.update(bArray, (short) (bOffset + 1), aLen);

	} // end of the constructor

	public static void install(byte[] bArray, short bOffset, byte bLength) {
		new UnLockAppletClass(bArray, bOffset, bLength).register();
	}

	public void process(APDU apdu) {

		if (selectingApplet()) {
			return;
		}
		byte[] buffer = apdu.getBuffer();
		byte CLA = (byte) (buffer[ISO7816.OFFSET_CLA] & 0xFF);
		byte INS = (byte) (buffer[ISO7816.OFFSET_INS] & 0xFF);
		if (CLA != CP_CLA) {
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		}

		switch (INS) {
		// first auth step
		case VERIFY_USER_PIN_INS:
			if (buffer[ISO7816.OFFSET_P2] == USER_PIN_PARAM)
				verifyUserPin(apdu);
			else
				ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
			break;
		// second auth step
		case SEND_PASSWORD_INS:
			if (PIN_AUTHENTICATION_SUCCESS)
				sendPassword(apdu);
			else
				ISOException.throwIt(SW_VERIFICATION_FAILED);
			break;
		// third step -> ACR request
		case AUTHORIZATION_ROOM_INS:
			if (PASSWD_AUTHENTICATION_SUCCESS)
				sendAuthorizationRoomRequest(apdu);
			else
				ISOException.throwIt(SW_UNAUTHORIZED_ACCESS);
			break;
		default:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}

	/* ---------------- User authentication ---------------- */

	/**
	 * @brief verify the inputed user PIN coming from the client with the built-in
	 *        OwnPin process
	 * @param apdu
	 */
	private void verifyUserPin(APDU apdu) {
		byte[] buffer = apdu.getBuffer();

		byte numBytes = buffer[ISO7816.OFFSET_LC];

		byte byteRead = (byte) (apdu.setIncomingAndReceive());

		if ((numBytes != MAX_PIN_LENGTH) || (byteRead != MAX_PIN_LENGTH))
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

		if (pin.check(buffer, ISO7816.OFFSET_CDATA, byteRead) == false)
			ISOException.throwIt(SW_VERIFICATION_FAILED);
		else
			PIN_AUTHENTICATION_SUCCESS = true;
	}

	/**
	 * @brief send the password to the Access Controller Applet calling the
	 *        `verifyPassword` method, and return a boolean accordingly
	 * @param apdu
	 */
	private void sendPassword(APDU apdu) {

		byte[] buffer = apdu.getBuffer();
		byte numBytes = buffer[ISO7816.OFFSET_LC];
		byte byteRead = (byte) (apdu.setIncomingAndReceive());

		if ((numBytes != 10) || (byteRead != 10))
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

		byte[] AccessControllerAID = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x01, 0x00 };
		AID AccessControllerAIDObject = new AID(AccessControllerAID, (short) 0, (byte) AccessControllerAID.length);

		if (AccessControllerIf == null)
			AccessControllerIf = (AccessControllerAppletInterface) JCSystem
					.getAppletShareableInterfaceObject(AccessControllerAIDObject, (byte) 0);
		if (AccessControllerIf == null) // if getting applet crashed
			ISOException.throwIt(ISO7816.SW_APPLET_SELECT_FAILED);

		if (AccessControllerIf.verifyPassword(apdu)) {
			PASSWD_AUTHENTICATION_SUCCESS = true;
		} else
			ISOException.throwIt(SW_WRONG_PASSWORD);
	}

	/* ---------------- Room authorization ---------------- */

	/**
	 * @brief send the apdu buffer with the room ID to the Action Applet, calling
	 *        the `verifyRoomAccess`
	 * @param apdu
	 */
	private void sendAuthorizationRoomRequest(APDU apdu) {
		byte[] ActionAID = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x02, 0x00 };
		AID ActionAIDObject = new AID(ActionAID, (short) 0, (byte) ActionAID.length);

		if (ActionIf == null)
			ActionIf = (ActionAppletInterface) JCSystem.getAppletShareableInterfaceObject(ActionAIDObject, (byte) 0);
		if (ActionIf == null) // if getting applet crashed
			ISOException.throwIt(ISO7816.SW_APPLET_SELECT_FAILED);

		if (ActionIf.sendACRRequest(apdu)) {
			ROOM_AUTHORIZATION_SUCESS = true;
			doUnlockAction(apdu);
		} else
			ISOException.throwIt(SW_UNAUTHORIZED_ACCESS);
	}

	/**
	 * @brief method called if the
	 * @param apdu
	 */
	private void doUnlockAction(APDU apdu) {
		if (ROOM_AUTHORIZATION_SUCESS) {
			
			// sending back a special door code to assure the client that the user is authenticated
			short le = apdu.setOutgoing();
			le = (short) UNLOCK_DOOR_CODE.length;
			apdu.setOutgoingLength(le);
			apdu.sendBytesLong(UNLOCK_DOOR_CODE, (short) 0, le);
		} else {
			ISOException.throwIt(SW_UNAUTHORIZED_ACCESS);
		}
		return;
	}
}
