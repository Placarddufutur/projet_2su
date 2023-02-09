package Client;

import java.io.*;
import java.net.Socket;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Scanner;
import java.util.TimeZone;

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
	public static final byte VERIFY_MASTER_PIN_INS = (byte) 0x21;
	public static final byte VERIFY_PASSWD_INS = (byte) 0x02;
	public static final byte VERIFY_MASTER_PASSWD_INS = (byte) 0x03;
	private static final byte AUTHORIZATION_ROOM_INS = (byte) 0x04;
	private static final byte WALLET_ACCESS_INS = (byte) 0x05;
	private static final byte WALLET_GET_BALANCE = (byte) 0x50;
	private static final byte CLOCK_IN_GET_LOGS = (byte) 0x51;
	private static final byte CLOCK_IN_ACCESS_REQUEST = (byte) 0x06;
	
	public static final byte USER_PIN_PARAM = (byte) 0x82;
	public static final byte MASTER_PIN_PARAM = (byte) 0x81;
	public static final byte DEBIT_COMMAND = (byte) 0x01;
	public static final byte CREDIT_COMMAND = (byte) 0x02;
	
	public static boolean MASTER_PIN_AUTHENTICATED = false;
	public static boolean USER_PIN_AUTHENTICATED = false;
	public static boolean MASTER_PASSWD_AUTHENTICATED = false;
	public static boolean USER_PASSWD_AUTHENTICATED = false;

	// ACR
	private static Hashtable<Byte, String> ACRTable = new Hashtable<>();
	final static byte[] UNLOCK_DOOR_CODE = { 0x64, 0x44 };
	final static byte[] TRANSACTION_ANSWER = { 0x65, 0x45 };
	final static byte[] CLOCK_IN_ANSWER = { 0x66, 0x46 };
	
	public static CadT1Client cad;

	@SuppressWarnings("resource")
	public static void main(String[] args) throws Exception {

		/* ---------------- Loading ACR ---------------- */

		ACRTable.put((byte) 0x45, "SA2.05");
		ACRTable.put((byte) 0x1b, "Hall");
		ACRTable.put((byte) 0x78, "Learning Center");
		ACRTable.put((byte) 0x3C, "SA2.21 (4AS)");

		/* ---------------- Javacard connexion ---------------- */

		boolean connexionEstablished = false;
		Socket sckCarte;
		System.out.println("En attente de connexion...");
		while (!connexionEstablished) {
			try {
				sckCarte = new Socket("localhost", 9025);
				sckCarte.setTcpNoDelay(true);
				BufferedInputStream input = new BufferedInputStream(sckCarte.getInputStream());
				BufferedOutputStream output = new BufferedOutputStream(sckCarte.getOutputStream());
				cad = new CadT1Client(input, output);
				connexionEstablished = true;
			} catch (Exception e) {
			}
		}

		try {
			cad.powerUp();
		} catch (Exception e) {
			System.out.println("Erreur lors de l'envoi de la commande \"Powerup\" à la Javacard");
			return;
		}
		
		byte userOrMasterIns = 0x00;
		byte userOrMasterPin = 0x00;
		boolean userChosen = false;
		boolean isMaster = false;
		while (!userChosen) {

			System.out.println();
			System.out.println("Client Javacard - Projet d'option");
			System.out.println("----------------------------");
			System.out.println();
			System.out.format("Selectionnez l'utilisateur sous lequel vous voulez vous connecter : \n\n");	
		
			// Displaying options
			System.out.println("\t-> 1 - Administrateur");
			System.out.println("\t-> 2 - Utilisateur");
			
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
					userChosen = true;
					userOrMasterPin = MASTER_PIN_PARAM;
					userOrMasterIns = VERIFY_MASTER_PIN_INS;
					isMaster = true;
				}
				else if (choice == 2) {
					userChosen = true;
					userOrMasterPin = USER_PIN_PARAM;
					userOrMasterIns = VERIFY_USER_PIN_INS;
					isMaster = false;
				}
				else {
					System.out.println("Erreur : Choix incorrect");
				}
			} else {
				System.out.println("Erreur : Choix incorrect");
			}
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
				apdu.command[Apdu.INS] = userOrMasterIns;
				apdu.command[Apdu.P1] = 0x00;
				apdu.command[Apdu.P2] = userOrMasterPin;

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
					if (isMaster) {
						System.out.println("MASTER PIN authentifié avec succès, passage à l'étape du mot de passe");
						MASTER_PIN_AUTHENTICATED = true;
						pinAuthenticated = true;
					} else {
						System.out.println("User PIN authentifié avec succès, passage à l'étape du mot de passe");
						USER_PIN_AUTHENTICATED = true;
						pinAuthenticated = true;
					}
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
				if (MASTER_PIN_AUTHENTICATED) {
					apdu.command[Apdu.INS] = ClientClass.VERIFY_MASTER_PASSWD_INS;
				} else {
					apdu.command[Apdu.INS] = ClientClass.VERIFY_PASSWD_INS;
				}
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
					if (MASTER_PIN_AUTHENTICATED) {
						System.out.println("Mot de passe valide, admin authentifié avec succès !");
						MASTER_PASSWD_AUTHENTICATED = true;
						passwordAuthenticated = true;
					} else {
						System.out.println("Mot de passe valide, utilisateur authentifié avec succès !");
						USER_PASSWD_AUTHENTICATED = true;
						passwordAuthenticated = true;
					}
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
			if (MASTER_PASSWD_AUTHENTICATED) {
				System.out.println("\t-> 4 - Créditer carte RU");
				System.out.println("\t-> 5 - Récupérer dernier relevé de présence");
			}
			
			System.out.println("Choix : ");
			
			@SuppressWarnings("resource")
			Scanner sc = new Scanner(System.in);
			String inputId = sc.nextLine();
			
			//Option input validation
			boolean isChoiceValid = false;
			int choice=0;
			try {
				choice = Integer.parseInt(inputId);
				if (choice > 0 && choice < 6 && MASTER_PASSWD_AUTHENTICATED) {
					isChoiceValid = true;
				}
				else if (choice > 0 && choice < 4)
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
				else if (choice == 4 && MASTER_PASSWD_AUTHENTICATED) {
					callCreditingRU();
				}
				else if (choice == 5 && MASTER_PASSWD_AUTHENTICATED) {
					callGetClockInLogs();
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
	
	public static void callClockIn() throws IOException, CadTransportException {
		
		System.out.println("Validation de l'appel en cours...");
		
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
		apdu.command[Apdu.INS] = ClientClass.CLOCK_IN_ACCESS_REQUEST;
		apdu.command[Apdu.P1] = 0x00;
		apdu.command[Apdu.P2] = 0x00;

		// Adding padding to input password
		byte[] amountArray = { getCurrentDayAsByte(), getCurrentHourAsByteWithTimeZone() };
		apdu.setDataIn(amountArray, amountArray.length);
		cad.exchangeApdu(apdu);
		
		if (apdu.getStatus() != 0x9000) {
			System.out.println("Erreur : appel impossible ! ");
		} else {
			if (Arrays.equals(apdu.dataOut, CLOCK_IN_ANSWER)) {
				
				System.out.println("===============\n" + "Appel effectué pour le cours de : " + (int) getCurrentHourAsByteWithTimeZone() + "h !\n"
				+ "===============\n");
				
			} else
				System.out.println("Erreur : Mauvaise R-APDU concernant l'accès à l'applet d'appel");
		}
		System.out.println("Débug : " + apdu);
		
	}

	
	public static void callOpenDoor() throws IOException, CadTransportException {

		
		System.out.println();
		System.out.println("Client Javacard - Projet d'option - Ouverture de porte");
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
	
	public static void callPaymentRU() throws IOException, CadTransportException {
		
		System.out.println();
		System.out.println("Client Javacard - Projet d'option - Paiement au RU");
		System.out.println("----------------------------");
		System.out.println();
		System.out.format("Indiquez le nombre de points du repas : \n\n", ClientClass.MAX_PASSWD_LENGTH);

		@SuppressWarnings("resource")
		Scanner sc = new Scanner(System.in);
		String inputId = sc.nextLine();		
		
		// Option input validation
		boolean isChoiceValid = false;
		try {
			int choice = Integer.parseInt(inputId);
			if (choice > 0 && choice <= 127)
				isChoiceValid = true;
		} catch (NumberFormatException e) {
			isChoiceValid = false;
		}
		if (isChoiceValid) {
			byte choice = (byte) Integer.parseInt(inputId);
			
			System.out.println("Demande de débit en cours...");
			
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
			apdu.command[Apdu.INS] = ClientClass.WALLET_ACCESS_INS;
			apdu.command[Apdu.P1] = 0x00;
			apdu.command[Apdu.P2] = DEBIT_COMMAND;

			// Adding padding to input password
			byte[] amountArray = { choice };
			apdu.setDataIn(amountArray, amountArray.length);
			cad.exchangeApdu(apdu);
			
			if (apdu.getStatus() != 0x9000) {
				System.out.println("Erreur : transaction impossible ! ");
			} else {
				if (Arrays.equals(apdu.dataOut, TRANSACTION_ANSWER)) {
					
					System.out.println("===============\n" + "Repas à " + (int) choice + " points débité !\n"
					+ "===============\n");
					
					apdu = new Apdu();
					apdu.command[Apdu.CLA] = 0x00;
					apdu.command[Apdu.INS] = (byte) 0xA4;
					apdu.command[Apdu.P1] = 0x04;
					apdu.command[Apdu.P2] = 0x00;

					byte[] WalletRUAppletAID = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x04, 0x00 };

					apdu.setDataIn(WalletRUAppletAID);

					cad.exchangeApdu(apdu);
					if (apdu.getStatus() != 0x9000) {
						System.out.println("Erreur : impossible de sélectionner l'applet UnLockApplet");
						System.exit(1);
					}
					
					apdu = new Apdu();
					apdu.command[Apdu.CLA] = ClientClass.CP_CLA;
					apdu.command[Apdu.INS] = ClientClass.WALLET_GET_BALANCE;
					apdu.command[Apdu.P1] = 0x00;
					apdu.command[Apdu.P2] = 0x00;

					// Adding padding to input password
					cad.exchangeApdu(apdu);
					
					if (apdu.getStatus() != 0x9000) {
						System.out.println("Erreur : transaction impossible ! ");
					} else {
						System.out.println("===============\n" + "Montant restant sur la carte : " + balanceToEuros(apdu.dataOut) + "€.\n"
							+ "===============\n");
					}
				} else
					System.out.println("Erreur : Mauvaise R-APDU concernant l'accès au porte-monnaie électronique");
			}
			System.out.println("Débug : " + apdu);

		} else {
			System.out
					.println("Option invalide, entrez un nombre de points entre 1 et 127 !\n");
		}
			
	}

	public static String byteArrayToHex(byte[] a) {
		StringBuilder sb = new StringBuilder(a.length * 2);
		for (byte b : a)
			sb.append(String.format("%02x", b));
		return sb.toString();
	}
	
	public static double balanceToEuros(byte[] a) {
	    int result = 0;
	    for (int i = 0; i < a.length; i++) {
	        result = (result << 8) | (a[i] & 0xff);
	    }
	    return result/100.0;
	}
	
	public static byte[] eurosToBalance(double euroCents) {
	    int euros = (int) Math.round(euroCents * 100);
	    byte[] result = new byte[2];
	    result[1] = (byte) (euros & 0xff);
	    result[0] = (byte) ((euros >> 8) & 0xff);
	    return result;
	}
	
	public static void callCreditingRU() throws IOException, CadTransportException {
		System.out.println();
		System.out.println("Client Javacard - Projet d'option - Paiement au RU");
		System.out.println("----------------------------");
		System.out.println();
		System.out.format("Indiquez le montant à créditer en € : \n\n", ClientClass.MAX_PASSWD_LENGTH);

		@SuppressWarnings("resource")
		Scanner sc = new Scanner(System.in);
		String inputId = sc.nextLine();		
		
		// Option input validation
		boolean isChoiceValid = false;
		try {
			double choice = Double.valueOf(inputId);
			if (choice > 0.0 && choice <= 327.67)
				isChoiceValid = true;
		} catch (NumberFormatException e) {
			isChoiceValid = false;
		}
		if (isChoiceValid) {
			double interChoice = Double.valueOf(inputId);
			byte[] choice = eurosToBalance(interChoice);
			
			System.out.println("Demande de crédit en cours...");
			
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
			apdu.command[Apdu.INS] = ClientClass.WALLET_ACCESS_INS;
			apdu.command[Apdu.P1] = 0x00;
			apdu.command[Apdu.P2] = CREDIT_COMMAND;

			// Adding padding to input password
			apdu.setDataIn(choice, choice.length);
			cad.exchangeApdu(apdu);
			
			if (apdu.getStatus() != 0x9000 && apdu.getStatus() != 0x6d00) {
				System.out.println("Erreur : transaction impossible ! ");
			} else {
				if (Arrays.equals(apdu.dataOut, TRANSACTION_ANSWER)) {
					
					System.out.println("===============\n" + "Carte créditée de " + interChoice + " € !\n"
					+ "===============\n");
					
					apdu = new Apdu();
					apdu.command[Apdu.CLA] = 0x00;
					apdu.command[Apdu.INS] = (byte) 0xA4;
					apdu.command[Apdu.P1] = 0x04;
					apdu.command[Apdu.P2] = 0x00;

					byte[] WalletRUAppletAID = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x04, 0x00 };

					apdu.setDataIn(WalletRUAppletAID);

					cad.exchangeApdu(apdu);
					if (apdu.getStatus() != 0x9000) {
						System.out.println("Erreur : impossible de sélectionner l'applet UnLockApplet");
						System.exit(1);
					}
					
					apdu = new Apdu();
					apdu.command[Apdu.CLA] = ClientClass.CP_CLA;
					apdu.command[Apdu.INS] = ClientClass.WALLET_GET_BALANCE;
					apdu.command[Apdu.P1] = 0x00;
					apdu.command[Apdu.P2] = 0x00;

					// Adding padding to input password
					cad.exchangeApdu(apdu);
					
					if (apdu.getStatus() != 0x9000 && apdu.getStatus() != 0x6d00) {
						System.out.println("Erreur : transaction impossible ! ");
					} else {
						System.out.println("===============\n" + "Montant actuel sur la carte après créditement : " + balanceToEuros(apdu.dataOut) + "€.\n"
							+ "===============\n");
					}
				} else
					System.out.println("Erreur : Mauvaise R-APDU concernant l'accès au porte-monnaie électronique");
			}
			System.out.println("Débug : " + apdu);

		} else {
			System.out
					.println("Option invalide, entrez un montant entre 0 et 327.67€ !\n");
		}
	}

	
	public static byte getCurrentDayAsByte() {
		Calendar calendar = Calendar.getInstance();
		int day = calendar.get(Calendar.DAY_OF_WEEK);
		switch (day) {
		  case Calendar.MONDAY:
		    return 0x00;
		  case Calendar.TUESDAY:
		    return 0x01;
		  case Calendar.WEDNESDAY:
		    return 0x02;
		  case Calendar.THURSDAY:
		    return 0x03;
		  case Calendar.FRIDAY:
		    return 0x04;
		  default:
		    return 0x05;
		}
	}

	
	
	public static byte getCurrentHourAsByteWithTimeZone() {
		Calendar calendar = Calendar.getInstance(TimeZone.getTimeZone("Europe/Paris"));
		int hour = calendar.get(Calendar.HOUR_OF_DAY);
		return (byte)hour;
	}
	
	
	public static void callGetClockInLogs() throws IOException, CadTransportException {
		
		System.out.println("Validation de l'appel en cours...");
		
		/* UnLockApplet Selection */
		Apdu apdu = new Apdu();
		apdu.command[Apdu.CLA] = 0x00;
		apdu.command[Apdu.INS] = (byte) 0xA4;
		apdu.command[Apdu.P1] = 0x04;
		apdu.command[Apdu.P2] = 0x00;

		byte[] ClockInAppletAID = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x05, 0x00 };

		apdu.setDataIn(ClockInAppletAID);

		cad.exchangeApdu(apdu);
		if (apdu.getStatus() != 0x9000) {
			System.out.println("Erreur : impossible de sélectionner l'applet ClockInApplet");
			System.exit(1);
		}
		
		/* Transmitting ID to UnLockApplet */
		apdu = new Apdu();
		apdu.command[Apdu.CLA] = ClientClass.CP_CLA;
		apdu.command[Apdu.INS] = ClientClass.CLOCK_IN_GET_LOGS;
		apdu.command[Apdu.P1] = 0x00;
		apdu.command[Apdu.P2] = 0x00;
		
		// apdu.setIncomingLength((short)117);

		cad.exchangeApdu(apdu);
		
		if (apdu.getStatus() != 0x9000) {
			System.out.println("Erreur : appel impossible ! ");
		} else {
			System.out.println("===============\n" + "Liste d'appel de l'étudiant : "  +  displayClockInLogs(apdu.dataOut)  + "\n"
				+ "===============\n");
		}
		System.out.println("Débug : " + apdu);
		
	}
	
	
	public static String displayClockInLogs(byte[] clockInLogs) {
		String display = new String();
		
	    display += ("\n  JOUR   | HEURE |  MATIERE   | PRESENCE\n");
	    display += ("---------|-------|------------|---------\n");
	    
	    for (int i = 0; i < clockInLogs.length; i += 13) {
	    	if (clockInLogs[i] != (byte) 0xff) {
		        int dayInt = clockInLogs[i] & 0xff;
		        String day = new String();
		        switch (dayInt) {
		        	case 0:
		        		day = "  Lundi ";
		        		break;
		        	case 1:
		        		day = "  Mardi ";
		        		break;
		        	case 2:
		        		day = "Mercredi";
		        		break;
		        	case 3:
		        		day = "  Jeudi ";
		        		break;
		        	case 4:
		        		day = "Vendredi";
		        		break;
	        		default:
	        			break;
		        }
		        
		        int hourInt = clockInLogs[i + 1] & 0xff;
		        String hour = new String();
		        if (hourInt < 10) {
		        	hour = " " + hourInt + "h";
		        } else {
		        	hour = hourInt + "h";
		        }
		        
		        String discipline = "";
		        for (int j = 2; j < 12; j++) {
		        	
		            discipline += (char)clockInLogs[i + j];
		        }
		        
		        String presence = new String();
		        if(clockInLogs[i + 12] != 0) {
		        	presence = "Présent";
		        } else {
		        	presence = "Absent";
		        }
		        	
		        
		        display += (day + " |  " + hour + "  | " + discipline + " | " + presence + "\n");
	    	}
	    }
		
		
		return display;
	}

}