package org.web3j;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.smartcardio.CardTerminalSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import javacard.framework.ISO7816;
import org.bouncycastle.util.encoders.Hex;
import org.web3j.scwallet.securechannel.SecureChannelSession;

import javax.smartcardio.*;
import java.security.Security;
import java.util.Arrays;
import java.util.Random;

public class CardSimulatorApplication {

    public static void main(String[] args) throws Exception {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        CardSimulator simulator = new CardSimulator();

        AID appletAID = AIDUtil.create("F000000001");
        byte[] instParams = Hex.decode("0F53746174757357616C6C657441707001000C313233343536373839303132");
//        simulator.installApplet(appletAID, com.licel.jcardsim.samples.HelloWorldApplet.class);
        simulator.installApplet(appletAID, WalletApplet.class, instParams, (short) 0, (byte) instParams.length);

        CardTerminal terminal = CardTerminalSimulator.terminal(simulator);
        Card apduCard = terminal.connect("*");
        CardChannel apduChannel = apduCard.getBasicChannel();
//        byte[] resp = simulator.selectAppletWithResult(appletAID);
//        System.out.println(ByteUtil.getSW(resp));

        CommandAPDU commandAPDU = new CommandAPDU(ISO7816.CLA_ISO7816, ISO7816.INS_SELECT, 4, 0, Hex.decode("F000000001"));
        ResponseAPDU selectAPDU = apduChannel.transmit(commandAPDU);

        if (selectAPDU.getData()[0] == ((byte) 0xA4)) {
            System.out.println(true);
        }
        if (selectAPDU.getData()[2] == ((byte) 0x8F)) {
            System.out.println(true);
        }

        if (selectAPDU.getData()[20] == ((byte) 0x80)) {
            System.out.println(true);
        }

        SecureChannelSession secureChannelSession = new SecureChannelSession(apduChannel,
                Arrays.copyOfRange(selectAPDU.getData(), 22, selectAPDU.getData().length - 7));
        byte[] challenge = new byte[32];
        Random random = new Random();
        random.nextBytes(challenge);
//        secureChannelSession.pair(challenge);
        secureChannelSession.openSecureChannelAndAuthenticate();

/*        CardChannel apduChannel = apduCard.getBasicChannel();

        simulator.selectApplet(appletAID);

        CommandAPDU commandAPDU = new CommandAPDU(0x00, 0x01, 0x00, 0x00);
        ResponseAPDU response = apduChannel.transmit(commandAPDU);

        assert response.getSW() == 0x90;*/
    }
}