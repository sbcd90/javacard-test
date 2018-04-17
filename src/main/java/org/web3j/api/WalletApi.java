package org.web3j.api;

import org.web3j.scwallet.wallet.Wallet;

import javax.smartcardio.Card;

public class WalletApi {
    private Wallet wallet;

    public WalletApi() {
        this.wallet = new Wallet();
    }

    public void initializeWallet(Card card) throws Exception {
        this.wallet.setCard(card);
        this.wallet.initialize();
    }
}