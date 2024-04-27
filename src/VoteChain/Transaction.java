package VoteChain;

import crypto.utils.Schnorr.SchnorrPK;
import crypto.utils.Schnorr.SchnorrSig;

/**
 * A class representing a VoteChain's transaction
 */
public class Transaction {
     SchnorrPK pkSig;
     SchnorrSig sig;
     String message;


    public Transaction(SchnorrPK pkSig, SchnorrSig sig, String message) {
        this.pkSig = pkSig;
        this.sig = sig;
        this.message = message;
    }

    @Override
    public String toString() {
        return "Transaction{" +
                "pkSig=" + pkSig +
                ", sig=" + sig +
                ", message='" + message + '\'' +
                '}';
    }
}
