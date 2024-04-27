package crypto.utils.thresholdElGamal;

import java.math.BigInteger;

//structures for ElGamal public-key

public class ElGamalPK {

    public ElGamalParams params;
    public BigInteger h; // security parameter

    public ElGamalPK(BigInteger h, ElGamalParams params) {
        this.params = params;
        this.h = h;
    }

    public ElGamalPK() {
    }

    public BigInteger getH() {
        return h;
    }

    @Override
    public String toString() {
        return "ElGamalPK{" +
                "params=" + params +
                ", h=" + h +
                '}';
    }
}