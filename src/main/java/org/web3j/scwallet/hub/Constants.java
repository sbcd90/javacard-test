package org.web3j.scwallet.hub;

import java.util.concurrent.TimeUnit;

public class Constants {

    static final String scheme = "pcsc";

    static final long refreshCycle = TimeUnit.SECONDS.toSeconds(5);

    static final long refreshThrottling = TimeUnit.MILLISECONDS.toMillis(500);
}