package crypto.utils;

import java.math.BigInteger;
import java.security.SecureRandom;

import static crypto.utils.Utils.isqr;

public class DLogParams {
    public BigInteger p,q,g;

    public DLogParams(BigInteger p, BigInteger q, BigInteger g) {
        this.p = p;
        this.q = q;
        this.g = g;
    }

    /**
     * create a new instance of Dlog parameters giving the triplet (p,q,g)
     * @param securityparameter the security parameter of the instance
     * @return the triplet containing the Dlog instance
     */
    public static DLogParams SetupDLogParams(int securityparameter) {

        DLogParams dlogparams = new DLogParams(BigInteger.ZERO, BigInteger.ZERO, BigInteger.ZERO);


        SecureRandom sc = new SecureRandom();
        // finding two prime numbers p and q such that p = 2q+1 with securityparameter number of bits
        do {
            dlogparams.q = BigInteger.probablePrime(securityparameter, sc);
            dlogparams.p = dlogparams.q.multiply(BigInteger.TWO).add(BigInteger.ONE);
        } while (!dlogparams.p.isProbablePrime(50)); // p is prime with probability 1-2^-50

        dlogparams.g = BigInteger.TWO;

        // finding a generator for the cyclic group given by prime p
        while (isqr(dlogparams.g, dlogparams.p) != 1) {
            dlogparams.g = dlogparams.g.add(BigInteger.ONE);
        }

        return dlogparams;
    }
}
