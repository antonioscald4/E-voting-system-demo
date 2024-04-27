package crypto.utils.thresholdElGamal;

import java.math.BigInteger;

// structures for ElGamal Ciphertexts

public class ElGamalCT {
    public BigInteger C, C2;

    public ElGamalCT(BigInteger C, BigInteger C2) {
        this.C = C;
        this.C2 = C2;
    }

    public ElGamalCT() {
        this.C = BigInteger.ONE;
        this.C2 = BigInteger.ONE;
    }

    /**
     * Construct a new Elgamal pair of ciphertext from a string
     * @param ct string in the format {C=(part one in decimal);C2=(part two in decimal)}
     */
    public ElGamalCT(String ct){
        String[] splits = ct.split("([;=}])");
        this.C = new BigInteger(splits[1]);
        this.C2 = new BigInteger(splits[3]);
    }

    public ElGamalCT(ElGamalCT CT) {
        this.C = CT.C;
        this.C2 = CT.C2;
    }

    @Override
    public String toString() {
        return "{C=" + C + ";C2=" + C2 + '}';
    }
}