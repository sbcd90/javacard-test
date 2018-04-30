package org.web3j;

import com.licel.jcardsim.samples.BaseApplet;
import javacard.framework.*;

public class HelloWorldApplet extends BaseApplet {

    private static final byte[] helloWorld = new byte[]{(byte) 'h', (byte) 'e', (byte) 'l', (byte) 'l', (byte) 'o',
            (byte) 'w', (byte) 'o', (byte) 'r', (byte) 'l', (byte) 'd'};
    private static final byte HW_CLA = (byte) 0x80;
    private static final byte HW_INS = (byte) 0x00;

    protected HelloWorldApplet(byte[] bArray, short bOffset, byte bLength) {
        if (bLength > 0) {
            byte iLen = bArray[bOffset];
            bOffset = (short) (bOffset + iLen + 1);
            byte var10000 = bArray[bOffset];
            bOffset = (short)(bOffset + 3);
            byte aLen = bArray[bOffset];
        }
        this.register();
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new HelloWorldApplet(bArray, bOffset, bLength);
    }

    @Override
    public void process(APDU apdu) throws ISOException {
        if (selectingApplet()) {
            return;
        }

        byte[] buffer = apdu.getBuffer();
        byte CLA = (byte) (buffer[ISO7816.OFFSET_CLA] & 0xFF);
        byte INS = (byte) (buffer[ISO7816.OFFSET_INS] & 0xFF);

        if (CLA != HW_CLA) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        switch (INS) {
            case HW_INS:
                getHelloWorld(apdu);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    private void getHelloWorld(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short length = (short) helloWorld.length;
        Util.arrayCopyNonAtomic(helloWorld, (short) 0, buffer, (short) 0, length);
        apdu.setOutgoingAndSend((short) 0, length);
    }
}