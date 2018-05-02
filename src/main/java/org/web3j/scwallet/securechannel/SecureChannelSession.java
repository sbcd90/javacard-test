package org.web3j.scwallet.securechannel;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.smartcardio.*;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import javacard.security.MessageDigest;
import java.util.Arrays;
import java.util.Random;

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

    private SecureRandom random;

    public SecureChannelSession(CardChannel apduChannel, byte[] keyData) {
        this.apduChannel = apduChannel;
        this.open = false;

        try {
            random = new SecureRandom();
            ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256k1");
            KeyPairGenerator g = KeyPairGenerator.getInstance("ECDH", "BC");
            g.initialize(ecSpec, random);

            KeyPair keyPair = g.generateKeyPair();

            publicKey = ((ECPublicKey) keyPair.getPublic()).getQ().getEncoded(false);
            KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH", "BC");
            keyAgreement.init(keyPair.getPrivate());

            ECPublicKeySpec cardKeySpec =
                    new ECPublicKeySpec(ecSpec.getCurve().decodePoint(keyData), ecSpec);
            ECPublicKey cardKey = (ECPublicKey) KeyFactory.getInstance("ECDSA", "BC").generatePublic(cardKeySpec);

            keyAgreement.doPhase(cardKey, true);
            secret = keyAgreement.generateSecret();

        } catch (Exception e) {
            throw new RuntimeException("Is BouncyCastle in the classpath?", e);
        }

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

    public void pair(byte[] sharedSecret) throws Exception {
        byte[] secretHash = new byte[sharedSecret.length];
        MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false)
                .doFinal(sharedSecret, (short) 0, (short) sharedSecret.length, secretHash, (short) 0);

        byte[] challenge = new byte[32];
        new Random().nextBytes(challenge);

        ResponseAPDU responseAPDU = this.pair(Constants.pairP1FirstStep, challenge);

        MessageDigest md = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);

        byte[] finalKey = new byte[secretHash.length + challenge.length];
        System.arraycopy(secretHash, 0, finalKey, 0, secretHash.length);
        System.arraycopy(challenge, 0, finalKey, secretHash.length, challenge.length);

        byte[] expectedCryptogram = new byte[challenge.length];
        md.doFinal(finalKey, (short) secretHash.length, (short) challenge.length, expectedCryptogram, (short) 0);
        byte[] cardCryptogram = Arrays.copyOfRange(responseAPDU.getData(), 0, 32);
        byte[] cardChallenge = Arrays.copyOfRange(responseAPDU.getData(), 32, responseAPDU.getData().length);

        if (!Arrays.equals(expectedCryptogram, cardCryptogram)) {
            throw new CardException("Invalid card cryptogram");
        }

        md.reset();
        finalKey = new byte[cardChallenge.length];
//        System.arraycopy(secretHash, 0, finalKey, 0, secretHash.length);
        System.arraycopy(cardChallenge, 0, finalKey, 0, cardChallenge.length);

        byte[] finalHash = new byte[finalKey.length];
        md.doFinal(finalKey, (short) 0, (short) finalKey.length, finalHash, (short) 0);
//        md.doFinal(finalKey, (short) 0, (short) finalKey.length, finalHash, (short) 0);
        responseAPDU = this.pair(Constants.pairP1LastStep, finalHash);

        md.reset();

        finalKey = new byte[secretHash.length + responseAPDU.getData().length - 1];
        System.arraycopy(secretHash, 0, finalKey, 0, secretHash.length);
        System.arraycopy(Arrays.copyOfRange(responseAPDU.getData(), 1, responseAPDU.getData().length), 0,
                finalKey, secretHash.length, responseAPDU.getData().length - 1);

        byte[] pairingKey = new byte[finalKey.length];
        md.doFinal(finalKey, (short) 0, (short) finalKey.length, pairingKey, (short) 0);
        this.setPairingKey(pairingKey);
        this.setPairingIndex(responseAPDU.getData()[0]);
    }

    public void unpair() throws Exception {
        if (this.getPairingKey() != null) {
            throw new CardException("Cannot unpair: not paired");
        }

        this.transmitEncrypted(org.web3j.scwallet.wallet.Constants.claSCWallet,
                org.web3j.scwallet.apdu.Constants.insUnpair,
                (byte) this.getPairingIndex(), (byte) 0, new byte[]{});

        this.setPairingKey(null);
        this.setIv(null);
    }

    public void openSecureChannelAndAuthenticate() throws Exception {
        if (this.getIv() != null) {
            throw new CardException("Session already opened");
        }

        ResponseAPDU responseAPDU = this.open();

        byte[] finalKey = new byte[this.getSecret().length + this.getPairingKey().length + Constants.scSecretLength];
        System.arraycopy(this.getSecret(), 0, finalKey, 0, this.getSecret().length);
        System.arraycopy(this.getPairingKey(), 0, finalKey, this.getSecret().length, this.getPairingKey().length);
        System.arraycopy(Arrays.copyOfRange(responseAPDU.getData(), 0, Constants.scSecretLength), 0,
                finalKey, this.getSecret().length + this.getPairingKey().length, Constants.scSecretLength);

        byte[] keyData = new byte[finalKey.length];
        MessageDigest.getInstance(MessageDigest.ALG_SHA_512, false)
                .doFinal(finalKey, (short) 0, (short) finalKey.length, keyData, (short) 0);
        this.setSessionEncKey(Arrays.copyOfRange(keyData, 0, Constants.scSecretLength));
        this.setSessionMacKey(Arrays.copyOfRange(keyData, Constants.scSecretLength, Constants.scSecretLength * 2));

        this.setIv(Arrays.copyOfRange(responseAPDU.getData(), Constants.scSecretLength, responseAPDU.getData().length));

        this.mutuallyAuthenticate();
    }

    private void mutuallyAuthenticate() throws Exception {
        byte[] data = new byte[Constants.scSecretLength];
        new Random().nextBytes(data);

        ResponseAPDU response = this.transmitEncrypted(org.web3j.scwallet.wallet.Constants.claSCWallet,
                org.web3j.scwallet.apdu.Constants.insMutuallyAuthenticate,
                (byte) 0, (byte) 0, data);

        if (response.getSW1() != 0x90 || response.getSW2() != 0x00) {
            throw new CardException("Got unexpected response from MUTUALLY_AUTHENTICATE - " + response.getSW1() + ", " +
            response.getSW2());
        }

        if (response.getData().length != Constants.scSecretLength) {
            throw new CardException("Response from MUTUALLY_AUTHENTICATE was " + response.getData().length + ", expected " +
            Constants.scSecretLength);
        }
    }

    private ResponseAPDU pair(int p1, byte[] data) throws Exception {
        CommandAPDU commandAPDU = new CommandAPDU(org.web3j.scwallet.wallet.Constants.claSCWallet,
                org.web3j.scwallet.apdu.Constants.insPair,
                p1, 0, data, 0);
        return this.transmit(commandAPDU);
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
            byte[] data = resp.getData();
            byte[] meta = new byte[]{(byte) data.length, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
            byte[] mac = Arrays.copyOf(data, this.getIv().length);
            data = Arrays.copyOfRange(data, this.getIv().length, data.length);

            byte[] plainData = this.decryptApdu(data);

            this.updateIV(meta, data);

            if (!Arrays.equals(this.getIv(), mac)) {
                throw new CardException("Invalid MAC");
            }
            return new ResponseAPDU(plainData);
        } else {
            return resp;
        }
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

    private ResponseAPDU open() throws Exception {
        CommandAPDU commandAPDU = new CommandAPDU(org.web3j.scwallet.wallet.Constants.claSCWallet,
                org.web3j.scwallet.apdu.Constants.insOpenSecureChannel,
                this.getPairingIndex(),
                0,
                this.getPublicKey(),
                0);
        return transmit(commandAPDU);
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