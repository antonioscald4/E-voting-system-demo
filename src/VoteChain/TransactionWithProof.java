package VoteChain;

import crypto.utils.Schnorr.SchnorrPK;
import crypto.utils.Schnorr.SchnorrSig;

/**
 * A class representing a VoteChain's transaction also containing the proof.
 */
public class TransactionWithProof extends Transaction{
    private final String ZKProof;

    public TransactionWithProof(SchnorrPK pkSig, SchnorrSig sig, String message, String ZKProof) {
        super(pkSig, sig, message);
        this.ZKProof = ZKProof;
    }

    @Override
    public String toString() {
        return "TransactionWithProof{" +
                "pkSig=" + pkSig +
                ", sig=" + sig +
                ", message='" + message + '\'' +
                ", ZKProof='" + ZKProof + '\'' +
                '}';
    }

    public String getZKProof() {
        return ZKProof;
    }
}
