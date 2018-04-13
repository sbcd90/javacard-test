package org.web3j;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

public class CardSimulatorApplication {

    public static void main(String[] args) {
        CardSimulator simulator = new CardSimulator();

        AID appletAID = AIDUtil.create("F000000001");
        simulator.installApplet(appletAID, HelloWorldApplet.class);

        simulator.selectApplet(appletAID);

        CommandAPDU commandAPDU = new CommandAPDU(0x00, 0x01, 0x00, 0x00);
        ResponseAPDU response = simulator.transmitCommand(commandAPDU);

        assert response.getSW() == 0x90;
    }
}