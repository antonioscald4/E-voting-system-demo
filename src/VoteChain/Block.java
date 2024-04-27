package VoteChain;

import crypto.utils.Utils;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;

/**
 * A class representing a VoteChain's block
 */
public class Block {

    private final String hash;
    private final String previousHash;
    private final Transaction transaction;
    private final LocalDateTime timeStamp;

    public Block(Transaction transaction, String previousHash, LocalDateTime timeStamp) throws NoSuchAlgorithmException {
        this.transaction = transaction;
        this.previousHash = previousHash;
        this.timeStamp = timeStamp;
        this.hash = calculateBlockHash();
    }

    /**
     * Compute the hash of a new block to be added
     * @return the hexadecimal representation of the block hash
     * @throws NoSuchAlgorithmException if digest algorithm is invalid
     */
    public String calculateBlockHash() throws NoSuchAlgorithmException {
        String dataToHash = previousHash + timeStamp + transaction;
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] bytes = digest.digest(dataToHash.getBytes());
        return Utils.bytesToHexString(bytes);
    }

    public String getHash() {
        return hash;
    }

    public Transaction getTransaction() {
        return transaction;
    }

    @Override
    public String toString() {
        return "Block{" +
                "hash='" + hash + '\'' +
                ", previousHash='" + previousHash + '\'' +
                ", transaction='" + transaction + '\'' +
                ", timeStamp=" + timeStamp +
                '}';
    }
}
