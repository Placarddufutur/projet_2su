package AccessControllerApplet;

import javacard.framework.*;
import javacard.security.*;
import share.AccessControllerAppletInterface;

public class AccessControllerAppletClass extends Applet implements AccessControllerAppletInterface {

	/* ---------------- Constants ---------------- */

	final static byte AC_CLA = (byte) 0x80;

	// INS codes
	final static byte VERIFY_PASSWD_INS = (byte) 0x02;
	final static byte GENERATE_SECRET_INS = (byte) 0x30;
	final static byte VERIFY_MASTER_PIN_INS = (byte) 0x21;

	// Password generation & storage
	private static byte[] secretTab;
	private static byte[] hashTab;
	private static byte[] xorTab;
	private static final byte MAX_PASSWD_LENGTH = (byte) 0x0a;

	// Auth verification errors
	final static short SW_VERIFICATION_FAILED = 0x6300;
	final static short SW_WRONG_PASSWORD = 0x6301;
	final static short SW_ID_NOT_FOUND = 0x6302;

	// PIN handling
	private static final byte MASTER_PIN_PARAM = (byte) 0x81;
	final static byte PIN_TRY_LIMIT = (byte) 0x03;
	final static byte MAX_PIN_LENGTH = (byte) 0x05;
	private boolean MASTER_PIN_AUTHENTICATED = false;
	OwnerPIN pin;

	// ACR table
	private static byte[] ACRIds = { 0x45, 0x1b, 0x78, 0x3C }; // 0x45 = SA2.05, 0x1b = Hall, 0x78 = Learning
																		// Center, 0x3c = SA2.21 (4AS)
	private static boolean[] ACRFlags = { true, true, true, false };

	private AccessControllerAppletClass(byte[] bArray, short bOffset, byte bLength) {

		// It is good programming practice to allocate
		// all the memory that an applet needs during
		// its lifetime inside the constructor
		pin = new OwnerPIN(PIN_TRY_LIMIT, MAX_PIN_LENGTH);
		byte iLen = bArray[bOffset]; // aid length
		bOffset = (short) (bOffset + iLen + 1);
		byte cLen = bArray[bOffset]; // info length
		bOffset = (short) (bOffset + cLen + 1);
		byte aLen = bArray[bOffset]; // applet data length

		// The installation parameters contain the PIN initialization value
		pin.update(bArray, (short) (bOffset + 1), aLen);
		register();
	}

	public static void install(byte bArray[], short bOffset, byte bLength) throws ISOException {
		new AccessControllerAppletClass(bArray, bOffset, bLength);
	}

	public boolean select() {

		// The applet declines to be selected
		// if the pin is blocked.
		if (pin.getTriesRemaining() == 0)
			return false;
		return true;

	}// end of select method

	public void deselect() {
		// reset the pin value
		pin.reset();

	}

	public Shareable getShareableInterfaceObject(AID clientAID, byte parameter) {
		return this;
	}

	// @Override
	public void process(APDU apdu) throws ISOException {

		// APDU object carries a byte array (buffer) to
		// transfer incoming and outgoing APDU header
		// and data bytes between card and CAD

		// At this point, only the first header bytes
		// [CLA, INS, P1, P2, P3] are available in
		// the APDU buffer.
		// The interface javacard.framework.ISO7816
		// declares constants to denote the offset of
		// these bytes in the APDU buffer

		byte[] buffer = apdu.getBuffer();
		if (apdu.isISOInterindustryCLA()) {
			if (buffer[ISO7816.OFFSET_INS] == (byte) (0xA4)) {
				return;
			} else {
				ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
			}
		}

		if (buffer[ISO7816.OFFSET_CLA] != AC_CLA)
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);

		// Main switch
		switch (buffer[ISO7816.OFFSET_INS]) {
		// Administrator auth
		case VERIFY_MASTER_PIN_INS:
			if (buffer[ISO7816.OFFSET_P2] == MASTER_PIN_PARAM)
				verifyMasterPin(apdu);
			else
				ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
			break;
		// Administrator step
		case GENERATE_SECRET_INS:
			if (MASTER_PIN_AUTHENTICATED)
				generateSecret(apdu);
			else
				ISOException.throwIt(SW_VERIFICATION_FAILED);
			break;
//		case VERIFY_PASSWD_INS:
//			verifyPassword(apdu);
//			break;
		default:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}

	}
	/* ---------------- Room management ---------------- */

	/**
	 * 
	 * @param buffer, the APDU buffer
	 * @return the value of the flag associated with the room Id contained in the
	 *         APDU buffer
	 */
	public boolean getACRAuthorisation(APDU apdu) {
		byte[] buffer = apdu.getBuffer();

		byte numBytes = buffer[ISO7816.OFFSET_LC];
		if ((numBytes != 1))
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

		byte[] roomId = new byte[1];
//		byte[] roomId = { 0x3C };
		Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, roomId, (short) 0, numBytes);

		for (short i = 0; i < ACRIds.length; i++) {
			if ((boolean) ((roomId[0] & 0xFF) == ACRIds[i]))
				return ACRFlags[i];
		}
		ISOException.throwIt(SW_ID_NOT_FOUND);
		return false;
	}
	/* ---------------- User Auth Management ---------------- */

	/**
	 * @param buffer, the APDU buffer
	 * @brief Compare the hash computed from the password inputed in the APDU buffer
	 *        (coming from the UnLockApplet) with the stored hash `hashTab`
	 */
	public boolean verifyPassword(APDU apdu) {
		boolean successfullyAuth = false;

		byte[] buffer = apdu.getBuffer();
		byte numBytes = buffer[ISO7816.OFFSET_LC];
		if ((numBytes != MAX_PASSWD_LENGTH))
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

		byte[] password = new byte[10];
		Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, password, (short) 0, numBytes);

		byte[] random = secretTab;
		byte[] resultXOR = new byte[random.length];

		for (short i = 0; i < 10; i++)
			resultXOR[i] = (byte) (random[i] ^ password[i++]);
		;

		byte[] hashedSecret = new byte[20];

//		MessageDigest messageDigest = MessageDigest.getInstance(MessageDigest.ALG_SHA, true);
//		messageDigest.doFinal(resultXOR, (short) 0, (short) (resultXOR.length), hashedSecret, (short) 0);

		if (Util.arrayCompare(resultXOR, (short) 0, xorTab, (short) 0, (short) (xorTab.length)) == (byte) 0) {
//		if (Util.arrayCompare(hashedSecret, (short) 0, hashTab, (short) 0, (short) (hashTab.length)) == (byte) 0) {
//		 hash are the same, user successfully auth w/ password
			successfullyAuth = true;

			// returning successful hash on R-APDU for debug
//			short le = apdu.setOutgoing();
//			if (hashedSecret.length < le) {
//				le = (short) hashedSecret.length;
//			}
//			apdu.setOutgoingLength(le);
//			apdu.sendBytesLong(hashedSecret, (short) 0, le);
//		} else {
//			ISOException.throwIt(SW_WRONG_PASSWORD);
		}
		return successfullyAuth;
	}

	/**
	 * 
	 * @param apdu the APDU buffer
	 * @brief method only available to the administrator, this method can only be
	 *        called if MASTER_PIN_AUTHENTICATED is set to true, generate the hash
	 *        related to the password that authenticate the user and store it into
	 *        hashTab
	 */
	public void generateSecret(APDU apdu) {
		// Formule : Hash_SHA1(random_Int ^ mdp_user)
		// Générer nombre aléatoire pour un utilisateur qui sera stocké, et passer au
		// XOR le
		// nombre aléatoire avec le mdp à hasher, puis hasher le tout en SHA-1

		byte[] buffer = apdu.getBuffer();

		byte numBytes = buffer[ISO7816.OFFSET_LC];

		byte byteRead = (byte) (apdu.setIncomingAndReceive());

		if ((numBytes != MAX_PASSWD_LENGTH) || (byteRead != MAX_PASSWD_LENGTH))
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

		byte[] secret = new byte[10];
		Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, secret, (short) 0, numBytes);

		byte[] random = new byte[10];
		RandomData randomData = RandomData.getInstance(RandomData.ALG_PSEUDO_RANDOM);
		randomData.generateData(random, (short) 0, (short) (random.length));

		byte[] resultXOR = new byte[random.length];

		for (short i = 0; i < 10; i++)
			resultXOR[i] = (byte) (random[i] ^ secret[i++]);

		byte[] hashedSecret = new byte[20];
		MessageDigest messageDigest = MessageDigest.getInstance(MessageDigest.ALG_SHA, false);
		messageDigest.doFinal(resultXOR, (short) 0, (short) (resultXOR.length), hashedSecret, (short) 0);

		secretTab = new byte[random.length];
		hashTab = new byte[hashedSecret.length];
		xorTab = new byte[resultXOR.length];
		Util.arrayCopyNonAtomic(random, (short) 0, secretTab, (short) 0, (short) random.length);
		Util.arrayCopyNonAtomic(hashedSecret, (short) 0, hashTab, (short) 0, (short) hashedSecret.length);
		Util.arrayCopyNonAtomic(resultXOR, (short) 0, xorTab, (short) 0, (short) resultXOR.length);

		short le = apdu.setOutgoing();

		if (hashTab.length < le) {
			le = (short) hashTab.length;
		}

		apdu.setOutgoingLength(le);
		apdu.sendBytesLong(hashTab, (short) 0, le);
		MASTER_PIN_AUTHENTICATED = false;
	}

	/* ---------------- Administrator auth ---------------- */

	/**
	 * @brief method only available to the administrator, authenticate the
	 *        administrator through a master PIN
	 * @param apdu the APDU buffer
	 */
	public boolean verifyMasterPin(APDU apdu) {

		byte[] buffer = apdu.getBuffer();

		byte numBytes = buffer[ISO7816.OFFSET_LC];

		if ((numBytes != MAX_PIN_LENGTH))
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		
		if (pin.check(buffer, ISO7816.OFFSET_CDATA, numBytes) == false)
			return false;
		else
			MASTER_PIN_AUTHENTICATED = true;
			return true;
	}
}
