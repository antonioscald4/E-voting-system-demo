package crypto.utils.Schnorr;

import crypto.utils.DLogParams;
import crypto.utils.Utils;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;

import static crypto.utils.DLogParams.SetupDLogParams;

public class Schnorr {

    /**
     * Generate a key pair of Schnorr signature scheme with a fixed security parameter
     * @param securityparameter the security parameter
     * @return the secret key containing also the public key of the signature scheme
     */
    public static SchnorrSK Setup(int securityparameter) {
        BigInteger h;

        SecureRandom sc = new SecureRandom();

        DLogParams params = SetupDLogParams(securityparameter);

        BigInteger s = new BigInteger(securityparameter, sc); // the private key, the randomness
        h = params.g.modPow(s, params.p); // the public key -> h = g^s mod p
        SchnorrPK PK = new SchnorrPK(params.p, params.q, params.g, h, securityparameter); // public key instance containing all the parameters

        return new SchnorrSK(s, PK);
    }


    /**
     * Generate a keypair of Schnorr signature scheme using given parameters
     * @param dlogparams the parameters according to which generate the signature
     * @param securityparameter security parameter of the keypair
     * @return the secret key containing also the public key of the signature scheme
     */
    public static SchnorrSK SetupDLogParamsFixed(DLogParams dlogparams, int securityparameter) {
        BigInteger h;

        SecureRandom sc = new SecureRandom();
        BigInteger s = new BigInteger(securityparameter, sc);
        h = dlogparams.g.modPow(s, dlogparams.p);
        SchnorrPK PK = new SchnorrPK(dlogparams.p, dlogparams.q, dlogparams.g, h, securityparameter);

        return new SchnorrSK(s, PK);
    }


    /**
     * Computes the hash in the Schnorr signature scheme
     * @param PK public key of the signature scheme
     * @param a
     * @param M the message to be hashed
     * @return the hash of the signature scheme, zero if failed
     */
    public static BigInteger HashToBigInteger(SchnorrPK PK, BigInteger a, String M) {
        // Hash PK+a+M to a BigInteger
        String msg = PK.g.toString() + PK.h.toString() + a.toString() + M;
        try { // hash a String using MessageDigest class
            MessageDigest h = MessageDigest.getInstance("SHA256");
            h.update(Utils.toByteArray(msg));
            BigInteger e = new BigInteger(h.digest());

            return e.mod(PK.q);
        } catch (Exception E) {
            E.printStackTrace();
        }

        return BigInteger.ZERO;
    }

    /**
     * Perform a signature of a message using Schnorr signature scheme
     * @param SK the secret key (with public key) of the scheme
     * @param M the message to be signed
     * @return a new signature of the message
     */
    public static SchnorrSig Sign(SchnorrSK SK, String M) {
        SecureRandom sc = new SecureRandom(); // generate secure random source
        BigInteger r = new BigInteger(SK.getPK().securityparameter, sc); // choose random r
        BigInteger a = SK.getPK().g.modPow(r, SK.getPK().p); // a=g^r mod p
        BigInteger e = HashToBigInteger(SK.getPK(), a, M); // e=H(PK,a,M)
        BigInteger z = r.add(e.multiply(SK.getS()).mod(SK.getPK().q)).mod(SK.getPK().q); // z=r+es mod q
        return new SchnorrSig(a, e, z); // (a,e,z) is the signature of M

    }

    /**
     * Perform a signature of a message given the Schnorr signature scheme using fixed "A", randomness "r" and a given public key
     * Shall be used to perform joint signature.
     * @param SK secret key of the scheme
     * @param M message to be signed
     * @param A
     * @param r randomness
     * @param pk public key of the scheme
     * @return
     */
    public static SchnorrSig Sign(SchnorrSK SK, String M, BigInteger A, BigInteger r, SchnorrPK pk){
        BigInteger a = SK.getPK().g.modPow(r, SK.getPK().p); // a=g^r mod p
        BigInteger e = HashToBigInteger(pk, A, M); // e=H(PK,a,M)
        BigInteger z = r.add(e.multiply(SK.getS()).mod(SK.getPK().q)).mod(SK.getPK().q); // z=r+es mod q
        return new SchnorrSig(a, e, z); // (a,e,z) is the signature of M
    }

    /**
     * compute the pair (secret, hidden secret) given the secret key of the Schnorr signature
     * @param SK secret key of the signature scheme
     * @return pair (secret, hidden secret)
     */
    public static Utils.Pair<BigInteger,BigInteger> computeA(SchnorrSK SK){
        SecureRandom sc = new SecureRandom(); // generate secure random source
        BigInteger r = new BigInteger(SK.getPK().securityparameter, sc); // choose random r
        return new Utils.Pair<>(r, SK.getPK().g.modPow(r, SK.getPK().p)); // a=g^r mod p
    }

    /**
     * Check the correctness of a Schnorr signature
     * @param sigma the signature
     * @param PK public key of the scheme
     * @param M message that has to be checked
     * @return the correctness of the signature
     */
    public static boolean Verify(SchnorrSig sigma, SchnorrPK PK, String M) {
        // sigma is the triple (a,e,z), PK is the pair (g,h)
        BigInteger e2 = HashToBigInteger(PK, sigma.a, M); // e2=H(PK,a,M)
        // crucial that we use the hash computed by ourself and not the challenge e in the signature
        // actually the value e in the signature is NOT needed
        BigInteger tmp = sigma.a.multiply(PK.h.modPow(e2, PK.p)).mod(PK.p); // tmp=ah^e2
        // compare tmp with g^z mod p
        return tmp.compareTo(PK.g.modPow(sigma.z, PK.p)) == 0;
    }





}