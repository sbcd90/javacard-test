package org.web3j.api;

import org.web3j.scwallet.wallet.Wallet;

public class WalletApi {
    private Wallet wallet;

    public WalletApi() {
        this.wallet = new Wallet();
    }

    public void initializeWallet() throws Exception {
        this.wallet.initialize();
    }
}