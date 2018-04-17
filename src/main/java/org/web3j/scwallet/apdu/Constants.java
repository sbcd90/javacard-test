package org.web3j.scwallet.apdu;

public class Constants {

    public static final byte claISO7816 = (byte) 0;

    public static final byte insSelect = (byte) 0xA4;

    public static final byte insGetResponse = (byte) 0xC0;

    public static final byte insPair = (byte) 0x12;

    public static final byte insUnpair = (byte) 0x13;

    public static final byte insOpenSecureChannel = (byte) 0x10;

    public static final byte insMutuallyAuthenticate = (byte) 0x11;

    public static final byte sw1GetResponse = (byte) 0x61;

    public static final byte sw1Ok = (byte) 0x90;
}