package crypto.utils.Schnorr;

import crypto.utils.Utils;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import static crypto.utils.Schnorr.Schnorr.HashToBigInteger;
import static crypto.utils.Schnorr.Schnorr.computeA;

public class SchnorrJointSignature {

    /**
     * Compute the joint public key of Schnorr signature using key-homomorphism
     * @param publicKeys list of schnorr public keys
     * @return the joint public key of schnorr
     */
    public static SchnorrPK generateJointPublicKey(List<SchnorrPK> publicKeys){

        BigInteger Y;
        Y = BigInteger.ONE;

        // homomorphism of Schnorr to compute the joint public key
        for(SchnorrPK pk: publicKeys){
            Y = Y.multiply(pk.h).mod(pk.p);
        }

        SchnorrPK pk1 = publicKeys.get(0);

        return new SchnorrPK(pk1.p,pk1.q,pk1.g, Y, pk1.securityparameter);
    }

    /**
     * Compute joint signature for Schnorr signature scheme
     * @param signatures list of Schnorr signatures
     * @param jointPublicKey joint public key of Schnorr
     * @param M the message to be signed
     * @return the joint signature of the message
     */
    public static SchnorrSig generateJointSignature(List<SchnorrSig> signatures, SchnorrPK jointPublicKey, String M){
        BigInteger A,E,Z;

        A = BigInteger.ONE;
        Z = BigInteger.ZERO;

        // homomorphism to generate the joint signature
        for(SchnorrSig sig: signatures){
            A = A.multiply(sig.a).mod(jointPublicKey.p);
            Z = Z.add(sig.z).mod(jointPublicKey.q);
        }

        E = HashToBigInteger(jointPublicKey, A, M);

        return new SchnorrSig(A,E, Z);
    }

    /**
     * Compute the joint A of the Schnorr signature scheme using homomorphism.
     * @param leA all the As to be combined
     * @param p the modulo size (parameter of the group)
     * @return joint A
     */
    public static BigInteger computeJointA(List<BigInteger> leA, BigInteger p){

        BigInteger A = BigInteger.ONE;

        for(BigInteger a : leA){
            A = A.multiply(a).mod(p);
        }
        return A;
    }

}
