package org.web3j.scwallet.hub;

import java.io.Serializable;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.locks.Lock;

public class Hub implements Serializable {

    private static final long serialVersionUID = 1L;

    private String dataDir;

    private Map<String, SmartCardPairing> pairings;

    private Instant refreshed;

    private Map<String, String> wallets;

    private Lock mutex;

    public void setDataDir(String dataDir) {
        this.dataDir = dataDir;
    }

    public String getDataDir() {
        return dataDir;
    }

    public void setPairings(Map<String, SmartCardPairing> pairings) {
        this.pairings = pairings;
    }

    public Map<String, SmartCardPairing> getPairings() {
        return pairings;
    }

    public void setRefreshed(Instant refreshed) {
        this.refreshed = refreshed;
    }

    public Instant getRefreshed() {
        return refreshed;
    }

    public void setWallets(Map<String, String> wallets) {
        this.wallets = wallets;
    }

    public Map<String, String> getWallets() {
        return wallets;
    }

    public void setMutex(Lock mutex) {
        this.mutex = mutex;
    }

    public Lock getMutex() {
        return mutex;
    }
}