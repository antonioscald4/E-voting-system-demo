package crypto.utils.thresholdElGamal;

import java.math.BigInteger;

//structures for ElGamal secret-key

public class ElGamalSK { // Secret-key of El Gamal
    private final BigInteger s;
    // s is random BigInteger from 1 to q where q is the order of g (g is in the PK)
    private final ElGamalPK PK; // PK of El Gamal

    public ElGamalSK(BigInteger s, ElGamalPK PK) {
        this.s = s;
        this.PK = PK;
    }

    public ElGamalPK getPK() {
        return PK;
    }

    public BigInteger getS() {
        return s;
    }

    @Override
    public String toString() {
        return "ElGamalSK{" +
                "s=" + s +
                ", PK=" + PK +
                '}';
    }
}