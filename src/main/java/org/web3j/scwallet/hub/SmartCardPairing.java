package org.web3j.scwallet.hub;

import java.io.Serializable;

public class SmartCardPairing implements Serializable {

    private static final long serialVersionUID = 1L;

    private byte[] publicKey;

    private int pairingIndex;

    private byte[] pairingKey;

    public void setPublicKey(byte[] publicKey) {
        this.publicKey = publicKey;
    }

    public byte[] getPublicKey() {
        return this.publicKey;
    }

    public void setPairingIndex(int pairingIndex) {
        this.pairingIndex = pairingIndex;
    }

    public int getPairingIndex() {
        return pairingIndex;
    }

    public void setPairingKey(byte[] pairingKey) {
        this.pairingKey = pairingKey;
    }

    public byte[] getPairingKey() {
        return pairingKey;
    }
}