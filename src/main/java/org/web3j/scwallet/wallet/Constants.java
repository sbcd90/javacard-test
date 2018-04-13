package org.web3j.scwallet.wallet;

import java.util.concurrent.TimeUnit;

public class Constants {

    static final byte[] appletAID = new byte[]{0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x57, 0x61, 0x6C, 0x6C, 0x65, 0x74, 0x41, 0x70, 0x70};

    static final byte claSCWallet = (byte) 0x80;

    static final byte tlvPubKey = (byte) 0x80;

    static final byte tlvPrivKey = (byte) 0x81;

    static final byte tlvChainCode = (byte) 0x82;

    static final byte loadKeyP1Ec = (byte) 0x01;

    static final byte loadKeyP1ExtEc = (byte) 0x02;

    static final byte insVerifyPin = (byte) 0x20;

    static final byte insSign = (byte) 0xC0;

    static final byte insLoadKey = (byte) 0xD0;

    static final byte insDeriveKey = (byte) 0xD1;

    static final byte insStatus = (byte) 0xF2;

    static final int deriveP1Assisted = 0x01;

    static final int deriveP1Append = 0x80;

    static final int deriveP2KeyPath = 0x00;

    static final int deriveP2PublicKey = 0x01;

    static final int statusP1WalletStatus = 0x00;

    static final int statusP1Path = 0x01;

    static final int signP1PrecomputedHash = 0x01;

    static final int signP2OnlyBlock = 0x81;

    static final int exportP1Any = 0x00;

    static final int exportP2Pubkey = 0x01;

    static final long selfDeriveThrottling = TimeUnit.SECONDS.toSeconds(1);

}