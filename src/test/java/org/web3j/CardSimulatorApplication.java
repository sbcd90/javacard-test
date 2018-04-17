package org.web3j;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.smartcardio.CardTerminalSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import org.web3j.api.WalletApi;

import javax.smartcardio.*;

public class CardSimulatorApplication {

    public static void main(String[] args) throws Exception {
        CardSimulator simulator = new CardSimulator();

        AID appletAID = AIDUtil.create("F000000001");
        simulator.installApplet(appletAID, com.licel.jcardsim.samples.HelloWorldApplet.class);

        CardTerminal terminal = CardTerminalSimulator.terminal(simulator);
        Card apduCard = terminal.connect("*");

        WalletApi walletApi = new WalletApi();
        walletApi.initializeWallet(apduCard);

/*        CardChannel apduChannel = apduCard.getBasicChannel();

        simulator.selectApplet(appletAID);

        CommandAPDU commandAPDU = new CommandAPDU(0x00, 0x01, 0x00, 0x00);
        ResponseAPDU response = apduChannel.transmit(commandAPDU);*/

//        assert response.getSW() == 0x90;
    }
}