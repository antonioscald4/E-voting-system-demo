package VotingEntities;

import VoteChain.VoteChain;
import crypto.utils.Schnorr.SchnorrPK;
import crypto.utils.Schnorr.SchnorrSK;
import crypto.utils.Schnorr.SchnorrSig;
import crypto.utils.thresholdElGamal.ElGamalCT;
import crypto.utils.thresholdElGamal.ElGamalPK;
import crypto.utils.thresholdElGamal.ThresholdElGamal;

import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

import static crypto.utils.Schnorr.Schnorr.Setup;
import static crypto.utils.Schnorr.Schnorr.Sign;

/**
 * A class representing a Voter simulation entity
 */
public class Voter{
    private SchnorrSK sk;


    public Voter() {

    }

    public void generateSignPair(int securityparameter){
        sk = Setup(securityparameter);
    }

    /**
     * Post the public key of the voter to the voting portal
     *
     * @param votingPortal the path to the voting portal file
     * @throws IOException
     */
    public void postPublicKey(String votingPortal) throws IOException {
        FileWriter writer = new FileWriter(votingPortal,true);
        // scrittura su file della public key di firma
        writer.write(sk.getPK().getH().toString() + '\n');
        writer.close();
    }

    @Override
    public String toString() {
        return "Voter{" +
                "sk=" + sk +
                '}';
    }


    /**
     * Simulate a new vote of a voter on the blockchain.
     * The vote is chosen randomly, then is encrypted using exponential elgamal,
     * then a valid proof of vote correctness is generated. Finally, the proof is signed
     * and a new transaction on the blockchain is performed.
     * @param blockchain the blockchain on which post the transaction
     * @param pkA joint public key of the authorities
     * @throws IOException can't write on the blockchain
     * @throws NoSuchAlgorithmException insertion of the vote failed
     */
    public BigInteger vote(VoteChain blockchain, ElGamalPK pkA) throws IOException, NoSuchAlgorithmException {
        BigInteger vote = new BigInteger(1, new Random()); // voto 0 o 1

        BigInteger r = ThresholdElGamal.getR(pkA.params.securityparameter);

        ElGamalCT encryptedVote = ThresholdElGamal.EncryptInTheExponent(pkA, vote, r);

        String ZKproof = generateZKProofVoteValid(pkA, vote, r);

        SchnorrSig voteSig = Sign(sk, encryptedVote+ZKproof);

        blockchain.insertVoteTransaction(pkA,  sk.getPK(), voteSig , encryptedVote, ZKproof);

        return vote;
    }

    /**
     * Create a new ZK proof on the correctness of the vote.
     * A simulated proof is presented, so the result will be always valid proof.
     * @param pkA joint public key of the authorities
     * @param m the vote
     * @param r the randomness used to cipher the vote
     * @return the proof of vote correctness
     */
    public String generateZKProofVoteValid(ElGamalPK pkA, BigInteger m, BigInteger r){
        return "successful proof";
    }

    public SchnorrPK getPKSig(){
        return sk.getPK();
    }


}
