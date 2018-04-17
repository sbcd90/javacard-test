package org.web3j.scwallet.wallet;

import org.web3j.scwallet.hub.Hub;
import org.web3j.scwallet.securechannel.SecureChannelSession;

import javax.smartcardio.Card;
import java.io.Serializable;
import java.util.Objects;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

public class Wallet implements Serializable {

    private static final long serialVersionUID = 1L;

    private Hub hub;

    private byte[] publicKey;

    private Lock lock;

    private Card card;

    private Session session;

    public Wallet() {
        this.lock = new ReentrantLock(true);
        this.session = new Session();
    }

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

        if (Objects.nonNull(this.getCard())) {
            SecureChannelSession channel = new SecureChannelSession(this.getCard().getBasicChannel());
            this.getSession().setChannel(channel);
            this.getSession().initialize();
            this.getLock().unlock();
        } else {
            this.getLock().unlock();
            throw new RuntimeException("Please specify card parameter");
        }
    }
}