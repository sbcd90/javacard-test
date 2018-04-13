package org.web3j.scwallet.securechannel;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.smartcardio.*;
import java.util.Arrays;

public class SecureChannelSession {

    private CardChannel apduChannel;

    private byte[] secret;

    private byte[] publicKey;

    private byte[] pairingKey;

    private byte[] sessionEncKey;

    private byte[] sessionMacKey;

    private byte[] iv;

    private int pairingIndex;

    private boolean open;

    public SecureChannelSession(CardChannel apduChannel) {
        this.apduChannel = apduChannel;
        this.open = false;
    }

    public void setCardChannel(CardChannel apduChannel) {
        this.apduChannel = apduChannel;
    }

    public CardChannel getCardChannel() {
        return apduChannel;
    }

    public void setSecret(byte[] secret) {
        this.secret = secret;
    }

    public byte[] getSecret() {
        return secret;
    }

    public void setPublicKey(byte[] publicKey) {
        this.publicKey = publicKey;
    }

    public byte[] getPublicKey() {
        return publicKey;
    }

    public void setPairingKey(byte[] pairingKey) {
        this.pairingKey = pairingKey;
    }

    public byte[] getPairingKey() {
        return pairingKey;
    }

    public void setSessionEncKey(byte[] sessionEncKey) {
        this.sessionEncKey = sessionEncKey;
    }

    public byte[] getSessionEncKey() {
        return sessionEncKey;
    }

    public void setSessionMacKey(byte[] sessionMacKey) {
        this.sessionMacKey = sessionMacKey;
    }

    public byte[] getSessionMacKey() {
        return sessionMacKey;
    }

    public void setIv(byte[] iv) {
        this.iv = iv;
    }

    public byte[] getIv() {
        return iv;
    }

    public void setPairingIndex(int pairingIndex) {
        this.pairingIndex = pairingIndex;
    }

    public int getPairingIndex() {
        return pairingIndex;
    }

    public ResponseAPDU transmitEncrypted(byte cla, byte ins, byte p1, byte p2, byte[] data) throws Exception {
        if (this.getIv() == null) {
            throw new CardException("Channel not open");
        }

        data = this.encryptApdu(data);

        byte[] meta = new byte[]{cla, ins, p1, p2, (byte) (data.length + Constants.scBlockSize), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

        this.updateIV(meta, data);

        byte[] fullData = new byte[this.getIv().length + data.length];
        System.arraycopy(this.getIv(), 0, fullData, 0, this.getIv().length);
        System.arraycopy(data, 0, fullData, this.getIv().length, data.length);

        CommandAPDU apdu = new CommandAPDU(cla, ins, p1, p2, fullData);
        ResponseAPDU resp = transmit(apdu);

        byte[] rmeta = new byte[]{(byte) resp.getData().length, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        byte[] rmac = Arrays.copyOf(resp.getData(), this.getIv().length);
        byte[] rdata = Arrays.copyOfRange(resp.getData(), this.getIv().length, resp.getData().length);

        byte[] plainData = decryptApdu(rdata);

        updateIV(rmeta, rdata);

        if (!Arrays.equals(this.getIv(), rmac)) {
            throw new RuntimeException("Invalid MAC in response");
        }

        ResponseAPDU rapdu = new ResponseAPDU(plainData);

        if (rapdu.getSW1() != 0x90) {
            throw new RuntimeException("Unexpected Response status");
        }
        return rapdu;
    }

    public ResponseAPDU transmit(CommandAPDU apdu) throws Exception {
        ResponseAPDU resp = apduChannel.transmit(apdu);

        if (resp.getSW() == 0x6982) {
            open = false;
        }

        if (open) {
            return resp;
        }
        throw new CardException("Card is not open");
    }

    public byte[] encryptApdu(byte[] data) throws Exception {
        if (data.length > Constants.maxPayloadSize) {
            throw new CardException(String.format("Payload of %d bytes exceeds maximum of %d", data.length, Constants.maxPayloadSize));
        }

        data = pad(data, (byte) 0x80);

        Cipher cipher = Cipher.getInstance("AES");
        SecretKey secretKey = new SecretKeySpec(this.getSessionEncKey(), 0, this.getSessionEncKey().length, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        return cipher.doFinal(data);
    }

    public byte[] decryptApdu(byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        SecretKey secretKey = new SecretKeySpec(this.getSessionEncKey(), 0, this.getSessionEncKey().length, "AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);

        byte[] ret = cipher.doFinal(data);
        return unpad(ret,(byte) 0x80);
    }

    public void updateIV(byte[] meta, byte[] data) throws Exception {
        data = pad(data, (byte) 0);

        Cipher cipher = Cipher.getInstance("AES");
        SecretKey secretKey = new SecretKeySpec(this.getSessionEncKey(), 0, this.getSessionEncKey().length, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        meta = cipher.doFinal(meta);
        data = cipher.doFinal(data);
        this.setIv(Arrays.copyOfRange(data, data.length - 32, data.length - 16));
    }

    private byte[] pad(byte[] data, byte terminator) {
        byte[] padded = new byte[(data.length / 16 + 1) * 16];
        System.arraycopy(data, 0, padded, 0, data.length);
        padded[data.length] = terminator;
        return padded;
    }

    private byte[] unpad(byte[] data, byte terminator) {
        for (int i=1; i <= 16; i++) {
            if (data[data.length - i] == 0) {
                continue;
            } else if (data[data.length - i] == terminator) {
                return Arrays.copyOfRange(data, 0, data.length - i);
            } else {
                throw new RuntimeException("Expected end of padding, got " + data[data.length - i]);
            }
        }
        throw new RuntimeException("Expected end of padding, got 0");
    }
}