package org.web3j.scwallet.wallet;

import org.web3j.scwallet.hub.Hub;

import javax.smartcardio.Card;
import java.io.Serializable;
import java.util.concurrent.locks.Lock;

public class Wallet implements Serializable {

    private static final long serialVersionUID = 1L;

    private Hub hub;

    private byte[] publicKey;

    private Lock lock;

    private Card card;

    private Session session;

    public void setHub(Hub hub) {
        this.hub = hub;
    }

    public Hub getHub() {
        return hub;
    }

    public void setPublicKey(byte[] publicKey) {
        this.publicKey = publicKey;
    }

    public byte[] getPublicKey() {
        return publicKey;
    }

    public void setLock(Lock lock) {
        this.lock = lock;
    }

    public Lock getLock() {
        return lock;
    }

    public void setCard(Card card) {
        this.card = card;
    }

    public Card getCard() {
        return card;
    }

    public void setSession(Session session) {
        this.session = session;
    }

    public Session getSession() {
        return session;
    }

    public void initialize() throws Exception {
        this.getLock().lock();
        this.getLock().unlock();

        this.getSession().initialize();
    }
}