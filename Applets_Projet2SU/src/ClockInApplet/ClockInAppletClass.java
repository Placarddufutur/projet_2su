package ClockInApplet;

import javacard.framework.*;
import share.ClockInAppletInterface;
import java.*;

public class ClockInAppletClass extends Applet implements ClockInAppletInterface {
	
	private static final byte GET_CLOCK_IN_LOGS = (byte) 0x51;
	
	private static final short SW_INITIALIZATION_ERROR = (short) 0x6401;
	private static final short SW_CLOCK_IN_ERROR = (short) 0x6402;
	
	private static final byte NUM_DAYS = (byte)5;
	private static final byte NUM_HOURS = (byte)8;
	private static final byte NUM_DISCIPLINE_LETTERS = (byte)10;
	
	private static byte[] schedule = new byte[NUM_DAYS*NUM_HOURS*NUM_DISCIPLINE_LETTERS];
	
	private static final short NUM_CLOCK_IN_LOG_MESSAGE = (short)13;
	private byte[] clockInLog = new byte[(short)1 * NUM_CLOCK_IN_LOG_MESSAGE];
	private short rows = (short)0;


	final static byte ClockIn_CLA = (byte) 0x80;
		
	private ClockInAppletClass() {
		
	}

	public static void install(byte bArray[], short bOffset, byte bLength) throws ISOException {
		
		for (byte i = (byte) 0x00; i < NUM_DAYS; i++) {
			for (byte j = (byte) 0x00; j < NUM_HOURS; j++) {
				for (byte k = (byte) 0x00; k < NUM_DISCIPLINE_LETTERS; k++) {
					switch (k) {
						case (byte) 0x00:
							setSchedule(i,j,k,(byte)0x42);
							break;
						case (byte) 0x01:
							setSchedule(i,j,k,(byte)0x69);
							break;
						case (byte) 0x02:
							setSchedule(i,j,k,(byte)0x70);
							break;
						case (byte) 0x03:
							setSchedule(i,j,k,(byte)0x42);
							break;
						case (byte) 0x04:
							setSchedule(i,j,k,(byte)0x69);
							break;
						case (byte) 0x05:
							setSchedule(i,j,k,(byte)0x70);
							break;
						case (byte) 0x06:
							setSchedule(i,j,k,(byte)0x42);
							break;
						case (byte) 0x07:
							setSchedule(i,j,k,(byte)0x6f);
							break;
						case (byte) 0x08:
							setSchedule(i,j,k,(byte)0x75);
							break;
						case (byte) 0x09:
							setSchedule(i,j,k,(byte)0x70);
							break;
						default:
							ISOException.throwIt(SW_INITIALIZATION_ERROR);
					} // "BipBipBoup" = {0x42, 0x69, 0x70, 0x42, 0x69, 0x70, 0x42, 0x6f, 0x75, 0x70});
				}
			}
		}
		new ClockInAppletClass().register();
	}
	
	public Shareable getShareableInterfaceObject(AID clientAID, byte parameter) {
		return this;
	}

	public void process(APDU apdu) throws ISOException {
		// TODO Auto-generated method stub
		
		if (selectingApplet()) {
			return;
		}
		
		byte[] buffer = apdu.getBuffer();
		byte CLA = (byte) (buffer[ISO7816.OFFSET_CLA] & 0xFF);
		byte INS = (byte) (buffer[ISO7816.OFFSET_INS] & 0xFF);
		if (CLA != ClockIn_CLA) {
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		}
		
		switch(INS) {
		case GET_CLOCK_IN_LOGS:
			getClockInLogs(apdu);
			break;
		default:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
		
	}
	
	
	private static void setSchedule(byte day, byte hour, byte indexDisciplineLetter, byte hexaLetter) {
	    short index = (short) ((day * NUM_HOURS * NUM_DISCIPLINE_LETTERS) + (hour * NUM_DISCIPLINE_LETTERS) + indexDisciplineLetter);
	    schedule[index] = hexaLetter;
	}
	
	private static byte[] getSchedule(byte day, byte hour) {
	    short startIndex = (short) ((day * NUM_HOURS * NUM_DISCIPLINE_LETTERS) + (hour * NUM_DISCIPLINE_LETTERS));
	    byte[] result = new byte[NUM_DISCIPLINE_LETTERS];
	    Util.arrayCopyNonAtomic(schedule, startIndex, result, (short)0, (short)NUM_DISCIPLINE_LETTERS);
	    return result;
	}

	
	public void addClockInLogRow(byte[] row) {
	    if (rows == (short) (clockInLog.length / NUM_CLOCK_IN_LOG_MESSAGE)) {
	        byte[] newClockInLog = new byte[(short)(clockInLog.length + NUM_CLOCK_IN_LOG_MESSAGE)];
	        Util.arrayCopyNonAtomic(clockInLog, (short)0, newClockInLog, (short)0, (short) clockInLog.length);
	        clockInLog = newClockInLog;
	    }
	    Util.arrayCopyNonAtomic(row, (short)0, clockInLog, (short) (rows * NUM_CLOCK_IN_LOG_MESSAGE), NUM_CLOCK_IN_LOG_MESSAGE);
	    rows++;
	}

	public byte[] getClockInLogValue(short row) {
	    byte[] clockInRow = new byte[NUM_CLOCK_IN_LOG_MESSAGE];
	    for (short i = 0; i < NUM_CLOCK_IN_LOG_MESSAGE; i++) {
	        clockInRow[i] = clockInLog[(short) (row * NUM_CLOCK_IN_LOG_MESSAGE + i)];
	    }
	    return clockInRow;
	}


	
	public void addClockInLogValue(short row, byte[] rangeValue) {
	    if (row == (short) (clockInLog.length / NUM_CLOCK_IN_LOG_MESSAGE)) {
	        addClockInLogRow(rangeValue);
	    } else {
	    	Util.arrayCopyNonAtomic(rangeValue, (short)0, clockInLog, (short) (row * NUM_CLOCK_IN_LOG_MESSAGE), NUM_CLOCK_IN_LOG_MESSAGE);
	    }
    }
	
	public boolean clockInRequest(APDU apdu) {
		
		byte[] buffer = apdu.getBuffer();
		byte numBytes = buffer[ISO7816.OFFSET_LC];
		boolean logDone = false;
		byte[] discipline = new byte[(short)10];
		byte[] clockInValues = new byte[NUM_CLOCK_IN_LOG_MESSAGE];
		
		if (numBytes != 2) {
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			return false;
		}
		
		byte[] dataIn = new byte[(short)2];
		
		Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, dataIn, (short) 0, numBytes);
		
		if ((byte) (dataIn[1]-(byte)0x08) < (byte) 0x06) {
			discipline = getSchedule(dataIn[0],(byte)(dataIn[1]-0x08));
			logDone = true;
		} else {
			discipline = getSchedule(dataIn[0],(byte)(dataIn[1]-0x0a));
			logDone = true;
		}
		

		Util.arrayCopyNonAtomic(dataIn, (short) 0, clockInValues, (short)0, (short) dataIn.length);
		Util.arrayCopyNonAtomic(discipline, (short) 0, clockInValues, (short)dataIn.length, (short) discipline.length);
		clockInValues[12] = (byte) 0x01;
		
		addClockInLogValue(rows, clockInValues);
		
		if (!logDone) {
			ISOException.throwIt(SW_CLOCK_IN_ERROR);
			return logDone;
		} else {
			return logDone;
		}
	}
	
	private void getClockInLogs(APDU apdu) {
		
		byte[] buffer = apdu.getBuffer();
		
		short le = apdu.setOutgoing();
		
		if (le < (short)2)
		   ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		
		
		apdu.setOutgoingLength((byte)0x75);
		
		short i;
		
		if (rows > 9) {
			for (i = (short) (clockInLog.length - 9*NUM_CLOCK_IN_LOG_MESSAGE); i < (short) clockInLog.length; i ++) {
				buffer[(short) (i - ((short) (clockInLog.length - 9*NUM_CLOCK_IN_LOG_MESSAGE)))] = clockInLog[i];
			}
		} else {
			for (i = (short)0; i < (short) clockInLog.length; i ++) {
				if (i == 117)
					break;
				buffer[i] = clockInLog[i];
			}
			for (short j = i; j < (short) 117; j ++) {
				buffer[j] = (byte) 0xff;
			}
		}

		apdu.sendBytes((short)0, (short)117);
	}
}
