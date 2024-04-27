package VoteChain;

import crypto.utils.Schnorr.Schnorr;
import crypto.utils.Schnorr.SchnorrPK;
import crypto.utils.Schnorr.SchnorrSig;
import crypto.utils.Utils;
import crypto.utils.thresholdElGamal.ElGamalCT;
import crypto.utils.thresholdElGamal.ElGamalPK;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.*;

import static crypto.utils.thresholdElGamal.ThresholdElGamal.Homomorphism;

/**
 * A class representing the VoteChain blockchain
 */
public class VoteChain {

    // the blockchain file used for simulations
    private final File blockchainDescriptor;

    private final List<Block> blocks;
    private final Map<BigInteger, Integer> votersPkMap; // the map with subscribed voters pks
    private final Map<BigInteger, LocalDateTime> voterLastTransactionTime; // map containing last transaction time for each voter

    private boolean votingInProgress; // true if voting is in progress, false otherwise
    private int indexOfStartVotingBlock, indexOfEndVotingBlock;
    private final Duration allowedTransactionInterval = Duration.ofMillis(500); // minimum voting interval for each voter, 1 hour in reality, 500 ms in test

    public VoteChain(String blockchainName) {
        this.blocks = new LinkedList<>();

        votingInProgress = false;
        indexOfStartVotingBlock = -1;
        indexOfEndVotingBlock = -1;

        votersPkMap = new HashMap<>();
        voterLastTransactionTime = new HashMap<>();
        blockchainDescriptor = new File(blockchainName);

    }

    /**
     * @return the last added block
     */
    public Block getLastBlock(){
        return blocks.get(blocks.size() - 1);
    }

    /**
     * Add the genesis block
     *
     * @param pkA the ElGamal public key of the authorities
     * @param jointPK the Schnorr signature public key of the authorities
     * @param jointSig the Schnorr signature of the transaction to insert into the block
     * @throws IOException
     * @throws NoSuchAlgorithmException
     */
    public void insertGenesisBlock(ElGamalPK pkA, SchnorrPK jointPK, SchnorrSig jointSig) throws IOException, NoSuchAlgorithmException {
        insertSignedTransaction(jointPK,jointSig, pkA.getH().toString());
    }

    /**
     * Add a list of voters transaction and also update the internal subscribed voters map
     *
     * @param jointPK the Schnorr signature public key of the authorities
     * @param jointSig the Schnorr signature of the transaction to insert into the block
     * @param votersPk the list of voters to insert as transaction into the blockchain
     * @throws IOException
     * @throws NoSuchAlgorithmException
     */
    public void insertPKTransactions(SchnorrPK jointPK, SchnorrSig jointSig, List<BigInteger> votersPk) throws IOException, NoSuchAlgorithmException {
        votersPk.forEach(voterPk -> votersPkMap.put(voterPk, votersPkMap.size()));
        insertSignedTransaction(jointPK,jointSig,votersPk.toString());
    }


    /**
     * Add a transaction to the blockchain (note that for simulation purpose we include only a transaction
     * into a block, since we do not simulate any consensus mechanism)
     *
     * @param transaction the Transaction to add
     * @throws NoSuchAlgorithmException
     * @throws IOException
     */
    public void addTransaction(Transaction transaction) throws NoSuchAlgorithmException, IOException {
        FileWriter writer = new FileWriter(blockchainDescriptor, true);

        String prevBlockHash;
        // if the chain is empty set prevBlock to 0
        if(blocks.size() > 0){
            prevBlockHash = getLastBlock().getHash();
        }else{
            prevBlockHash = "0";
        }

        blocks.add(new Block(transaction, prevBlockHash, LocalDateTime.now()));
        // updates the blockchain file
        writer.write(blocks.get(blocks.size()-1).toString());
        writer.write('\n');
        writer.close();
    }

    /**
     * Add a transaction to the blockchain specifying signature and message
     *
     * @param pk the signature pk
     * @param sig the signature for the message
     * @param message the message to include into the transaction
     * @throws IOException
     * @throws NoSuchAlgorithmException
     */
    public void insertSignedTransaction(SchnorrPK pk, SchnorrSig sig, String message) throws IOException, NoSuchAlgorithmException {
        Transaction transaction = new Transaction(pk,sig, message);
        if(Schnorr.Verify(transaction.sig, transaction.pkSig, transaction.message)) {
            addTransaction(transaction);
        }
    }

    /**
     * Add a transaction to the blockchain specifying signature, message and a ZK proof
     *
     * @param pk the signature pk
     * @param sig the signature for the message
     * @param message the message to include into the transaction
     * @param ZKProof the ZKProof to include into the transaction
     * @throws IOException
     * @throws NoSuchAlgorithmException
     */
    public void insertSignedTransactionWithProof(SchnorrPK pk, SchnorrSig sig, String message, String ZKProof) throws IOException, NoSuchAlgorithmException {
        TransactionWithProof transaction = new TransactionWithProof(pk,sig, message,ZKProof);
        if(Schnorr.Verify(transaction.sig, transaction.pkSig, transaction.message+transaction.getZKProof()))
            addTransaction(transaction);
    }

    /**
     * Add a decryption contributes transaction to the blockchain
     *
     * @param pk the signature pk
     * @param sig the signature for the message
     * @param message the message to include into the transaction
     * @param ZKProof the ZKProof to include into the transaction
     * @param wj the dec contribute
     * @param uj the randomness ciphertext part
     * @param pkAj the pkAj of encryption
     * @throws IOException
     * @throws NoSuchAlgorithmException
     */
    public void insertDecContributeTransaction(SchnorrPK pk, SchnorrSig sig, String message, String ZKProof,
                                               BigInteger wj, BigInteger uj, ElGamalPK pkAj) throws IOException, NoSuchAlgorithmException {
        if(verifyZKProofOfDecryption(ZKProof, wj, pkAj, uj))
            insertSignedTransactionWithProof(pk, sig, message, ZKProof);
    }

    /**
     * Add a vote transaction to the blockchain specifying signature, message and a ZK proof
     *
     * @param pka the pka for vote encryption ZK proof
     * @param pk the signature pk
     * @param sig the signature for the message
     * @param encrVote the vote to include into the transaction
     * @param ZKProof the ZKProof to include into the transaction
     * @throws IOException
     * @throws NoSuchAlgorithmException
     */
    public void insertVoteTransaction(ElGamalPK pka, SchnorrPK pk, SchnorrSig sig, ElGamalCT encrVote, String ZKProof) throws IOException, NoSuchAlgorithmException {
        // controlli
        if(votersPkMap.containsKey(pk.getH()) &&  //presente nella blockchain
        verifyZKProofOfVote(ZKProof, pka, encrVote) && // check validità zero knowledge proof voto 0 o 1
        votingInProgress &&  //controllo stato votazione in corso
        checkLastTransaction(pk,LocalDateTime.now())){ // controllo del tempo votazione

            //insertSignedTransaction(pk, sig, encrVote.toString());
            insertSignedTransactionWithProof(pk,sig,encrVote.toString(), ZKProof);

            // aggiunta nella mappa del tempo corrente transazione votante
            voterLastTransactionTime.put(pk.getH(), LocalDateTime.now());

        }

    }

    /**
     * @param pk the pk of the voter
     * @param currentTimeTransaction the time of the current transaction
     * @return true only if the time interval is greater than allowedTransactionInterval
     */
    public boolean checkLastTransaction(SchnorrPK pk, LocalDateTime currentTimeTransaction){
        if(voterLastTransactionTime.containsKey(pk.getH())){
            Duration differenceInTime = Duration.between(voterLastTransactionTime.get(pk.getH()), currentTimeTransaction);
            return differenceInTime.compareTo(allowedTransactionInterval) > 0;  // restituisce vero solo se l'intervallo di tempo è superiore al minimo richiesto
        }
        return true;
    }

    /**
     * Simulates the Zero-Knowledge proof of encrypting 0 or 1
     */
    public boolean verifyZKProofOfVote(String ZKProof, ElGamalPK pka, ElGamalCT encrVote){
        return true;
    }

    /**
     * Simulates the Zero-Knowledge proof of decryption contributes
     */
    public boolean verifyZKProofOfDecryption(String ZKProof, BigInteger wj, ElGamalPK pkaj, BigInteger uj){
        return true;
    }


    /**
     * Add a start vote transaction to the blockchain
     *
     * @param startvotejointpk the signature pk
     * @param startvotejointSig the signature for the message
     * @param message the message to include into the transaction
     * @throws IOException
     * @throws NoSuchAlgorithmException
     */
    public void insertStartTransaction(SchnorrPK startvotejointpk, SchnorrSig startvotejointSig, String message) throws IOException, NoSuchAlgorithmException {
        votingInProgress = true; // votazione è iniziata
        insertSignedTransaction(startvotejointpk ,startvotejointSig, message);
        indexOfStartVotingBlock = blocks.size()-1;
    }

    /**
     * Add a stop vote transaction to the blockchain
     *
     * @param stopvotejointpk the signature pk
     * @param stopvotejointSig the signature for the message
     * @param message the message to include into the transaction
     * @throws IOException
     * @throws NoSuchAlgorithmException
     */
    public void insertStopTransaction(SchnorrPK stopvotejointpk, SchnorrSig stopvotejointSig, String message) throws IOException, NoSuchAlgorithmException {
        votingInProgress = false; // votazione è terminata
        insertSignedTransaction(stopvotejointpk ,stopvotejointSig, message);
        indexOfEndVotingBlock = blocks.size()-1;
    }

    // filtraggio + verifica

    // TODO: questo restituisce il ciphertext complessivo (cambiare nome)

    /**
     * Count and filter last votes of all voters
     *
     * @param pk the ElGamal pk used to encrypt the votes
     * @return a ElGamalCT encrypting the sum of votes of candidate 1
     */
    public ElGamalCT countVotes(ElGamalPK pk) {
        //blocchi con le transazioni di voto

        Map<BigInteger, String> filteredVotes = new HashMap<>();
        //List<Utils.Pair<BigInteger,String>> filteredVotes = new ArrayList<>();

        for(int i=indexOfStartVotingBlock+1; i<indexOfEndVotingBlock; i++){
            //filtraggio voti duplicati
            TransactionWithProof transaction = (TransactionWithProof)blocks.get(i).getTransaction();
            filteredVotes.put(transaction.pkSig.getH(), transaction.message);
        }

        // tutti gli ultimi voti validi dei votanti
        // moltiplicazione -> omomorfismo su t. el gamal
        List<String> messages = new LinkedList<>(filteredVotes.values());

        return Homomorphism(pk, messages);
    }


    /**
     * @return a list of the decryption contributes of the authorities (which is located on the blockchain)
     */
    public BigInteger[] getAuthorityDecryptContributes(){

        List<BigInteger> W = new ArrayList<>();

        for(int i=indexOfEndVotingBlock+1; i < blocks.size(); i++){
            TransactionWithProof transaction = (TransactionWithProof)blocks.get(i).getTransaction();
            W.add(new BigInteger(transaction.message));
        }

        return W.toArray(new BigInteger[0]);
    }


    /**
     * Execute exhaustive search on the value to obtain the number of votes associated to candidate 1
     * @param value is a big integer such that value = g ^ x
     * @param g
     * @param p
     * @param maxNumOfVoters the max value of x
     * @return the exponent of g^x
     */
    public BigInteger bruteforceGetVotesTo1(BigInteger value, BigInteger g, BigInteger p, BigInteger maxNumOfVoters){
        BigInteger i;

        for(i = BigInteger.ZERO; i.compareTo(maxNumOfVoters) < 0; i = i.add(BigInteger.ONE) ){
            BigInteger val = g.modPow(i, p); // g^i mod p
            if(val.compareTo(value) == 0){ // g^i mod p == value
                return i; // found the exponent of the dlog -> number of voters
            }
        }

        return new BigInteger("-1"); // bruteforce did not found a solution

    }
}
