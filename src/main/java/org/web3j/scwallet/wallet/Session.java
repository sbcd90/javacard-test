package org.web3j.scwallet.wallet;

import org.apache.commons.lang3.tuple.Pair;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.web3j.scwallet.securechannel.SecureChannelSession;

import java.io.Serializable;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Random;

public class Session implements Serializable {

    private static final long serialVersionUID = 1L;

    private Wallet wallet;

    private SecureChannelSession channel;

    private boolean verified;

    public void setWallet(Wallet wallet) {
        this.wallet = wallet;
    }

    public Wallet getWallet() {
        return wallet;
    }

    public void setChannel(SecureChannelSession channel) {
        this.channel = channel;
    }

    public SecureChannelSession getChannel() {
        return channel;
    }

    public void setVerified(boolean verified) {
        this.verified = verified;
    }

    public boolean isVerified() {
        return verified;
    }

    public void initialize() throws Exception {
        ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256k1");
        KeyPairGenerator g = KeyPairGenerator.getInstance("ECDH", "BC");
        g.initialize(ecSpec);

        KeyPair keyPair = g.generateKeyPair();

        byte[] chainCode = new byte[32];
        new Random().nextBytes(chainCode);

        byte[] publicKey = ((ECPublicKey) keyPair.getPublic()).getQ().getEncoded(false);
        byte[] privateKey = ((ECPrivateKey) keyPair.getPrivate()).getD().toByteArray();

        Pair<byte[], Byte> preparedData = prepareData(publicKey, privateKey, chainCode);
        this.channel.transmitEncrypted(Constants.claSCWallet, Constants.insLoadKey,
                preparedData.getRight(), (byte) 0, preparedData.getLeft());
    }

    private Pair<byte[], Byte> prepareData(byte[] publicKey, byte[] privateKey, byte[] chainCode) {
        int privLen = privateKey.length;
        int privOff = 0;

        if (privateKey[0] == 0x00) {
            privOff++;
            privLen--;
        }

        int off = 0;
        int totalLength = publicKey == null ? 0: (publicKey.length + 2);
        totalLength += (privLen + 2);
        totalLength += chainCode == null ? 0: (chainCode.length + 2);

        if (totalLength > 127) {
            totalLength += 3;
        } else {
            totalLength += 2;
        }

        byte[] data = new byte[totalLength];
        data[off++] = (byte) 0xA1;

        if (totalLength > 127) {
            data[off++] = (byte) 0x81;
            data[off++] = (byte) (totalLength - 3);
        } else {
            data[off++] = (byte) (totalLength - 2);
        }

        if (publicKey != null) {
            data[off++] = Constants.tlvPubKey;
            data[off++] = (byte) publicKey.length;
            System.arraycopy(publicKey, 0, data, off, publicKey.length);
            off += publicKey.length;
        }

        data[off++] = Constants.tlvPrivKey;
        data[off++] = (byte) privLen;
        System.arraycopy(privateKey, privOff, data, off, privLen);
        off += privLen;

        byte p1;

        if (chainCode != null) {
            p1 = Constants.loadKeyP1ExtEc;
            data[off++] = (byte) Constants.tlvChainCode;
            data[off++] = (byte) chainCode.length;
            System.arraycopy(chainCode, 0, data, off, chainCode.length);
        } else {
            p1 = Constants.loadKeyP1Ec;
        }
        return Pair.of(data, p1);
    }
}