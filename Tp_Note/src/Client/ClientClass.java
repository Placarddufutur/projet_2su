package Client;

import java.io.*;
import java.net.Socket;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Scanner;

import com.sun.javacard.apduio.Apdu;
import com.sun.javacard.apduio.CadT1Client;
import com.sun.javacard.apduio.CadTransportException;

public class ClientClass {

	/* ---------------- Constants ---------------- */

	// Auth
	public static final int MAX_PIN_LENGTH = 5;
	public static final int MAX_PASSWD_LENGTH = 10;

	// APDU INS
	public static final byte CP_CLA = (byte) 0x80;
	public static final byte VERIFY_USER_PIN_INS = (byte) 0x20;
	public static final byte VERIFY_PASSWD_INS = (byte) 0x02;
	private static final byte AUTHORIZATION_ROOM_INS = (byte) 0x04;
	public static final byte USER_PIN_PARAM = (byte) 0x82;

	// ACR
	private static Hashtable<Byte, String> ACRTable = new Hashtable<>();
	final static byte[] UNLOCK_DOOR_CODE = { 0x64, 0x44 };
	
	public static CadT1Client cad;

	@SuppressWarnings("resource")
	public static void main(String[] args) throws Exception {

		/* ---------------- Loading ACR ---------------- */

		ACRTable.put((byte) 0x45, "SA2.05");
		ACRTable.put((byte) 0x1b, "Hall");
		ACRTable.put((byte) 0x78, "Learning Center");
		ACRTable.put((byte) 0x3C, "SA2.21 (4AS)");

		/* ---------------- Javacard connexion ---------------- */

		Socket sckCarte;
		try {
			sckCarte = new Socket("localhost", 9025);
			sckCarte.setTcpNoDelay(true);
			BufferedInputStream input = new BufferedInputStream(sckCarte.getInputStream());
			BufferedOutputStream output = new BufferedOutputStream(sckCarte.getOutputStream());
			cad = new CadT1Client(input, output);
		} catch (Exception e) {
			System.out.println("Erreur : impossible de se connecter à la Javacard");
			return;
		}

		try {
			cad.powerUp();
		} catch (Exception e) {
			System.out.println("Erreur lors de l'envoi de la commande \"Powerup\" à la Javacard");
			return;
		}

		/* ---------------- UI ---------------- */
		boolean pinAuthenticated = false;
		while (!pinAuthenticated) {
			System.out.println();
			System.out.println("Client Javacard - Projet d'option");
			System.out.println("----------------------------");
			System.out.println();
			System.out.format("Entrez votre code PIN Utilisateur : (Longueur = %d)\n", ClientClass.MAX_PIN_LENGTH);

			@SuppressWarnings("resource")
			Scanner sc = new Scanner(System.in);
			String inputPin = sc.nextLine();

			// ------> PIN Auth
			boolean isPinNumeric = true;
			try {
				@SuppressWarnings("unused")
				int Value = Integer.parseInt(inputPin);
			} catch (NumberFormatException e) {
				isPinNumeric = false;
			}
			if (inputPin.length() == ClientClass.MAX_PIN_LENGTH && isPinNumeric) {

				/* UnLockApplet Selection */
				Apdu apdu = new Apdu();
				apdu.command[Apdu.CLA] = 0x00;
				apdu.command[Apdu.INS] = (byte) 0xA4;
				apdu.command[Apdu.P1] = 0x04;
				apdu.command[Apdu.P2] = 0x00;

				byte[] UnLockAppletAID = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x00 };

				apdu.setDataIn(UnLockAppletAID);
				cad.exchangeApdu(apdu);
				if (apdu.getStatus() != 0x9000) {
					System.out.println("Erreur : impossible de sélectionner l'applet UnLockApplet");
				}

				/* PIN transmission to UnLockApplet */
				apdu = new Apdu();
				apdu.command[Apdu.CLA] = ClientClass.CP_CLA;
				apdu.command[Apdu.INS] = ClientClass.VERIFY_USER_PIN_INS;
				apdu.command[Apdu.P1] = 0x00;
				apdu.command[Apdu.P2] = ClientClass.USER_PIN_PARAM;

				// Putting PIN into data format
				byte[] inputPinBytes = new byte[ClientClass.MAX_PIN_LENGTH];
				int[] inputPinInt = new int[ClientClass.MAX_PIN_LENGTH];
				for (int i = 0; i < ClientClass.MAX_PIN_LENGTH; i++) {
					inputPinInt[i] = inputPin.charAt(i) - '0';
					inputPinBytes[i] = (byte) inputPinInt[i];
				}

				apdu.setDataIn(inputPinBytes, ClientClass.MAX_PIN_LENGTH);
				cad.exchangeApdu(apdu);

				if (apdu.getStatus() != 0x9000) {
					System.out.println("Erreur à la transmission du PIN, entrez un PIN valide");
					System.out.println(apdu);
				} else {
					// if status word is 0x9000 -> user PIN is valid
					System.out.println("PIN authentifié avec succès, passage à l'étape du mot de passe");
					pinAuthenticated = true;
				}
			} else {
				System.out.format("Le PIN est dans un format invalide, entrez un entier d'une longueur = %d\n",
						ClientClass.MAX_PIN_LENGTH);
			}
		}

		// ------> Password Auth
		boolean passwordAuthenticated = false;
		while (!passwordAuthenticated) {
			System.out.println();
			System.out.println("Client Javacard - Projet d'option");
			System.out.println("----------------------------");
			System.out.println();
			System.out.format("Entrez le mot de passe : (longueur maximum = %d)\n", ClientClass.MAX_PASSWD_LENGTH);

			@SuppressWarnings("resource")
			Scanner sc = new Scanner(System.in);
			String inputPassword = sc.nextLine();

			// Password input validation
			if (inputPassword.length() > 0 && inputPassword.length() <= ClientClass.MAX_PASSWD_LENGTH) {

				/* UnLockApplet Selection */
				Apdu apdu = new Apdu();
				apdu.command[Apdu.CLA] = 0x00;
				apdu.command[Apdu.INS] = (byte) 0xA4;
				apdu.command[Apdu.P1] = 0x04;
				apdu.command[Apdu.P2] = 0x00;

				byte[] UnLockAppletAID = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x00 };

				apdu.setDataIn(UnLockAppletAID);

				cad.exchangeApdu(apdu);
				if (apdu.getStatus() != 0x9000) {
					System.out.println("Erreur : impossible de sélectionner l'applet UnLockApplet");
					System.exit(1);
				}

				/* Password transmission to UnLockApplet */
				apdu = new Apdu();
				apdu.command[Apdu.CLA] = ClientClass.CP_CLA;
				apdu.command[Apdu.INS] = ClientClass.VERIFY_PASSWD_INS;
				apdu.command[Apdu.P1] = 0x00;
				apdu.command[Apdu.P2] = 0x00;

				// Adding padding to input password
				byte[] inputPasswordBytes = new byte[ClientClass.MAX_PASSWD_LENGTH];
				System.arraycopy(inputPassword.getBytes(), 0, inputPasswordBytes, 0, inputPassword.length());
				apdu.setDataIn(inputPasswordBytes, ClientClass.MAX_PASSWD_LENGTH);
				cad.exchangeApdu(apdu);

				if (apdu.getStatus() != 0x9000) {
					System.out.println("Mot de passe invalide");
					System.out.println(apdu);
				} else {
					// if status word is 0x9000, it means the user PIN is valid, proceeding to
					// password auth
					System.out.println("Mot de passe valide, utilisateur authentifié avec succès !");
					passwordAuthenticated = true;
				}
			} else
				System.out.format("Le mot de passe est dans un format invalide, entrez un mot d'une longueur maximum = %d\n",
						ClientClass.MAX_PASSWD_LENGTH);
		}

		// ------> Room selection
		boolean quit = false;
		while (!quit) {
			
			System.out.println();
			System.out.println("Client Javacard - Projet d'option");
			System.out.println("----------------------------");
			System.out.println();
			System.out.format("Selectionnez le service qui vous intéresse : \n\n");	
		
			// Displaying options
			System.out.println("\t-> 1 - Appel en cours");
			System.out.println("\t-> 2 - Ouverture de salle");
			System.out.println("\t-> 3 - Paiement au RU");
			
			System.out.println("Choix : ");
			
			@SuppressWarnings("resource")
			Scanner sc = new Scanner(System.in);
			String inputId = sc.nextLine();
			
			//Option input validation
			boolean isChoiceValid = false;
			int choice=0;
			try {
				choice = Integer.parseInt(inputId);
				if (choice > 0 && choice < 4)
					isChoiceValid = true;
			} catch (NumberFormatException e) {
				isChoiceValid = false;
			}
			
			if (isChoiceValid) {
				if (choice == 1) {
					callClockIn();
				}
				else if (choice == 2) {
					callOpenDoor();
				}
				else if (choice == 3) {
					callPaymentRU();
				}
				else {
					System.out.println("Erreur : Choix incorrect");
				}
			} else {
				System.out.println("Erreur : Choix incorrect");
			}
		}

		try {
			cad.powerDown();
		} catch (Exception e) {
			System.out.println("Erreur lors de l'envoi de la commande Powerdown à la Javacard");
			return;
		}
	}
	
	public static void callClockIn() {
		
	}

	
	public static void callOpenDoor() throws IOException, CadTransportException {

		
		System.out.println();
		System.out.println("Client Javacard - Projet d'option");
		System.out.println("----------------------------");
		System.out.println();
		System.out.format("Selectionnez une salle à ouvrir parmi les suivantes : \n\n", ClientClass.MAX_PASSWD_LENGTH);

		// Displaying options
		Enumeration<Byte> ACREnum = ACRTable.keys();
		int i = 1;
		while (ACREnum.hasMoreElements()) {
			// Getting the key of a particular entry
			byte key = ACREnum.nextElement();

			// Print and display the Rank and Name
			System.out.println(
					"\t-> " + i + " - " + ACRTable.get(key) + "(id: 0x" + String.format("%02X", key) + ")");
			i++;
		}
		System.out.println("Choix : ");

		@SuppressWarnings("resource")
		Scanner sc = new Scanner(System.in);
		String inputId = sc.nextLine();

		// Option input validation
		boolean isChoiceValid = false;
		try {
			int choice = Integer.parseInt(inputId);
			if (choice > 0 && choice <= ACRTable.size())
				isChoiceValid = true;
		} catch (NumberFormatException e) {
			isChoiceValid = false;
		}
		if (isChoiceValid) {
			int choice = Integer.parseInt(inputId);
			byte keyChoice = (byte) ACRTable.keySet().toArray()[choice - 1]; // choice-1 here because we started the
																				// count at
			// i=1 for
			// UX purposes
			System.out.println("Requête de l'accès à " + ACRTable.get(keyChoice) + "...");

			/* UnLockApplet Selection */
			Apdu apdu = new Apdu();
			apdu.command[Apdu.CLA] = 0x00;
			apdu.command[Apdu.INS] = (byte) 0xA4;
			apdu.command[Apdu.P1] = 0x04;
			apdu.command[Apdu.P2] = 0x00;

			byte[] UnLockAppletAID = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x00 };

			apdu.setDataIn(UnLockAppletAID);

			cad.exchangeApdu(apdu);
			if (apdu.getStatus() != 0x9000) {
				System.out.println("Erreur : impossible de sélectionner l'applet UnLockApplet");
				System.exit(1);
			}

			/* Transmitting ID to UnLockApplet */
			apdu = new Apdu();
			apdu.command[Apdu.CLA] = ClientClass.CP_CLA;
			apdu.command[Apdu.INS] = ClientClass.AUTHORIZATION_ROOM_INS;
			apdu.command[Apdu.P1] = 0x00;
			apdu.command[Apdu.P2] = 0x00;

			// Adding padding to input password
			byte[] roomIdArray = { keyChoice };
			apdu.setDataIn(roomIdArray, roomIdArray.length);
			cad.exchangeApdu(apdu);

			if (apdu.getStatus() != 0x9000) {
				System.out.println("Accès non autorisé à la salle : " + ACRTable.get(keyChoice));
			} else {
				if (Arrays.equals(apdu.dataOut, UNLOCK_DOOR_CODE))
					System.out.println("===============\n" + ACRTable.get(keyChoice) + " accès autorisé, porte ouverte !\n"
							+ "===============\n");
				else
					System.out.println("Erreur : Mauvaise R-APDU concernant l'accès à la salle");
			}
			System.out.println("Débug : " + apdu);

		} else {
			System.out
					.println("Option invalide, entrez un nombre correspondant à une option parmi celles affichées !\n");
		}
	
	}
	
	public static void callPaymentRU() {
		
	}

	public static String byteArrayToHex(byte[] a) {
		StringBuilder sb = new StringBuilder(a.length * 2);
		for (byte b : a)
			sb.append(String.format("%02x", b));
		return sb.toString();
	}

}