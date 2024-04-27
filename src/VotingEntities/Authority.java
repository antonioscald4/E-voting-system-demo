package VotingEntities;

import VoteChain.VoteChain;
import crypto.utils.DLogParams;
import crypto.utils.Schnorr.Schnorr;
import crypto.utils.Schnorr.SchnorrPK;
import crypto.utils.Schnorr.SchnorrSK;
import crypto.utils.Schnorr.SchnorrSig;
import crypto.utils.Utils;
import crypto.utils.thresholdElGamal.ElGamalCT;
import crypto.utils.thresholdElGamal.ElGamalPK;
import crypto.utils.thresholdElGamal.ElGamalSK;

import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;

import static crypto.utils.Schnorr.Schnorr.SetupDLogParamsFixed;
import static crypto.utils.Schnorr.Schnorr.computeA;

/**
 * A class representing an Authority simulation entity
 */
public class Authority {
    private SchnorrSK sk;
    private ElGamalPK pka;
    private ElGamalSK ska;
    private final DLogParams pqg;


    public Authority(DLogParams pqg){
        this.pqg = pqg;
    }

    public void generateSignPair(int securityparameter){
        sk = SetupDLogParamsFixed(pqg,securityparameter);
    }

    public void setElGamalPair(ElGamalPK pk,ElGamalSK sk){
        pka = pk;
        ska = sk;
    }

    public SchnorrPK getPk(){
        return sk.getPK();
    }

    /**
     * Compute the decryption contribute given a message
     * @param message message from which the decryption contribute is evaluated
     * @param pk public key of elgamal
     * @return decryption contribute wj
     */
    public BigInteger computeWj(ElGamalCT message, ElGamalPK pk){
        return message.C2.modPow(ska.getS(), pk.params.p);
    }

    /**
     * Sign with Schnorr the message with sk
     *
     * @param message the massage to sign
     * @return the signature
     */
    public SchnorrSig sign(String message){
        //contributi di decifratura
        return Schnorr.Sign(sk, message);

    }

    /**
     * Simulate publish of the decryption contribute by an authority on the blockchain.
     * The message containing the contribute and its zkproof is signed with Schnorr signature scheme.
     * @param pkA joint public key of elgamal
     * @param totalvotesOfOne ciphertexts containing the votes from which obtain the decryption contributes
     * @param blockchain the blockchain on which publish the computation
     */
    public void publishDecryptionContribute(ElGamalPK pkA, ElGamalCT totalvotesOfOne, VoteChain blockchain){

        BigInteger wj = computeWj(totalvotesOfOne, pkA);
        String ZKProofContributeValid = generateZKProofDecryptionContributeValid(wj,ska.getPK(), totalvotesOfOne.C2);

        SchnorrSig contributeSig = sign(wj.toString()+ZKProofContributeValid);

        try {
            blockchain.insertDecContributeTransaction(sk.getPK(), contributeSig, wj.toString(), ZKProofContributeValid,
                    wj, totalvotesOfOne.C2, pkA);

        } catch (IOException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

    }

    /**
     * @return contributes for Schnorr Joint Signature
     */
    public Utils.Pair<BigInteger,BigInteger> produceContributesForAggregateSignature(){
        return computeA(sk);
    }

    /**
     * Generate a new ZK proof ensuring that the decryption contribute is valid.
     * The proof is simulated, so the response is always the same and positive.
     * @param wj the decryption contribute
     * @param pkaj the public key of the authority
     * @param uj the constant value of the elgamal ciphertext
     * @return valid proof
     */
    public String generateZKProofDecryptionContributeValid(BigInteger wj, ElGamalPK pkaj, BigInteger uj){
        return "proof valid";
    }

    /**
     * Compute the partial signatures for joint signature
     *
     * @param M the message to sign
     * @param A the a contributes
     * @param R the randomnesses
     * @param joinedSigPk the jointSigPk
     * @return the partial signature
     */
    public  SchnorrSig computeSignature(String M, BigInteger A, BigInteger R, SchnorrPK joinedSigPk){
        return Schnorr.Sign(sk,M, A, R, joinedSigPk);
    }

    @Override
    public String toString() {
        return "Authority{" +
                "sk=" + sk +
                ", pka=" + pka +
                ", ska=" + ska +
                '}';
    }
}
