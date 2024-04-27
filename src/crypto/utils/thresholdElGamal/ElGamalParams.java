package crypto.utils.thresholdElGamal;

import java.math.BigInteger;

public class ElGamalParams {

    public BigInteger g, p, q; // description of the group and public-key h=g^s
    public int securityparameter; // security parameter

    public ElGamalParams(BigInteger p, BigInteger q, BigInteger g, int securityparameter) {
        this.p = p;
        this.q = q;
        this.g = g;
        this.securityparameter = securityparameter;
    }



}
