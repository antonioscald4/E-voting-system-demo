package app;

import VoteChain.VoteChain;
import VotingEntities.Authority;
import VotingEntities.Voter;
import crypto.utils.DLogParams;
import crypto.utils.Schnorr.*;
import crypto.utils.Utils;
import crypto.utils.thresholdElGamal.ElGamalCT;
import crypto.utils.thresholdElGamal.ElGamalPK;
import crypto.utils.thresholdElGamal.ElGamalParams;
import crypto.utils.thresholdElGamal.ElGamalSK;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

import static crypto.utils.DLogParams.SetupDLogParams;
import static crypto.utils.thresholdElGamal.ThresholdElGamal.*;

/**
 * A class which simulates the vote process.
 */
public class EVoteApp {

    /**
     * Creates a list of Voter simulation entities
     *
     * @param voterNum the number of Voters to create
     * @param securityParameter the security parameters for blockchain signatures generation
     * @return the list of created Voters
     */
    public static List<Voter> votersCreator(int voterNum, int securityParameter){

        List<Voter> voterList = new LinkedList<>();

        for(int i=0; i<voterNum; i++){
            Voter voter = new Voter();
            voter.generateSignPair(securityParameter);
            voterList.add(voter);
        }

        return voterList;
    }

    /**
     * Creates a list of Authority simulation entities
     *
     * @param na the number of Authority to create
     * @param securityParameter the security parameters for blockchain signatures generation
     * @return the list of created Authority
     */
    public  static List<Authority> authoritiesCreator(int na, int securityParameter){
        DLogParams pqg = SetupDLogParams(securityParameter);

        // creazione delle autorità
        List<Authority> authorities = new ArrayList<>(na);
        for(int i=0; i < na; i++) authorities.add(new Authority(pqg));
        return authorities;
    }


    public static Utils.Pair<SchnorrPK, SchnorrSig> authoritiesCreateJointSignature(int authoritiesInvolvedInVote, List<Authority> authorities, List<SchnorrPK> pkSigAj, String message){

        List<BigInteger> leR = new ArrayList<>(authoritiesInvolvedInVote);
        List<BigInteger> leA = new ArrayList<>(authoritiesInvolvedInVote);
        List<SchnorrSig> signatures = new ArrayList<>(authoritiesInvolvedInVote);

        for(Authority auth : authorities){
            Utils.Pair<BigInteger, BigInteger> AR = auth.produceContributesForAggregateSignature();
            leR.add(AR.t);
            leA.add(AR.u);
        }

        SchnorrPK joinedSigPk = SchnorrJointSignature.generateJointPublicKey(pkSigAj);
        BigInteger A = SchnorrJointSignature.computeJointA(leA, pkSigAj.get(0).getP());

        for(int i=0; i < authoritiesInvolvedInVote; i++){
            signatures.add(authorities.get(i).computeSignature(message,A,leR.get(i),joinedSigPk));
        }

        SchnorrSig joinedSig =  SchnorrJointSignature.generateJointSignature(signatures,joinedSigPk, message); // producing the joint signature of the authorities

        return new Utils.Pair<>(joinedSigPk, joinedSig);
    }

    /**
     * Run the simulation
     */
    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InterruptedException {

        int authoritiesInvolvedInVote = 15;
        int voterNumber = 10;

        // using this parameters requires a lot of time for simulating all the voting process
        // for 15 authorities and 10 voters. This effort, in reality, will be distributed over
        // these entities.
        int schnorrSecurityParameter = 512;  // 512 in real application, 64 for testing
        int elgamalSecurityParameter = 2048; // 2048 in real application, 64 for testing

        String votingPortal = "./voting_portal.txt";

        String blockchainName = "./VotingBlockchain.txt";
        VoteChain blockchain;

        //create a fresh voting portal and blockchain
        Utils.removeFileIfExists(votingPortal);
        Utils.removeFileIfExists(blockchainName);

        System.out.println("-".repeat(75));
        System.out.println("\t".repeat(6) + "EVote System Simulation ");
        System.out.println(" voterNumber = " + voterNumber
                + ", schnorrSecurityParam = " + schnorrSecurityParameter
                + ", elgamalSecurityParam = " + elgamalSecurityParameter);
        System.out.println("-".repeat(75));

        //creazione autorità
        //List<SchnorrSK> skSigAj = new ArrayList<>(authoritiesInvolvedInVote);
        List<SchnorrPK> pkSigAj = new ArrayList<>(authoritiesInvolvedInVote);
        List<Authority> authorities = authoritiesCreator(authoritiesInvolvedInVote,schnorrSecurityParameter);
        System.out.println("\t Authorities simulation entities creation done!");

        //creazione votanti
        List<Voter> voters = votersCreator(voterNumber, schnorrSecurityParameter);

        // creazione di blockchain
        blockchain = new VoteChain(blockchainName);

        System.out.println("\t Voters simulation entities creation done!");

        //INIZIALIZZAZIONE

        // le autorità effettuano protocollo generazione chiave distribuito per
        // ottenere public key combinata e secret key per ciascuno (threshold)

        ElGamalParams params = SetupParameters(elgamalSecurityParameter);
        ElGamalPK pkA = new ElGamalPK(); // chiave pubblica complessiva
        ElGamalSK[] skAj = LagrangeShamirSecretSharing(params, authoritiesInvolvedInVote, pkA); // lista chiavi private

        // ciascuna autorità salva la propria coppia per la cifratura
        for(int i=0; i < authoritiesInvolvedInVote; i++){
            authorities.get(i).setElGamalPair(skAj[i].getPK(), skAj[i]);
        }

        // generazione coppia firma digitale per ciascuna delle autorità
        for(int i=0; i < authoritiesInvolvedInVote; i++){
            authorities.get(i).generateSignPair(schnorrSecurityParameter);
            pkSigAj.add(authorities.get(i).getPk());
        }

        Utils.Pair<SchnorrPK, SchnorrSig> pk_Sig = authoritiesCreateJointSignature(authoritiesInvolvedInVote, authorities, pkSigAj, pkA.getH().toString());
        // ottenimento di firma e chiave pubblica firma associata alla chiave pubblica elgamal complessiva
        SchnorrSig elgamaljointSig = pk_Sig.u;
        SchnorrPK  elgamaljointpk = pk_Sig.t;

        System.out.println("\t Authorities keys generation done!");

        //aggiunta del blocco genesi

        blockchain.insertGenesisBlock(pkA,elgamaljointpk, elgamaljointSig);

        System.out.println("\t VoteChain genesys block added!");

        // REGISTRAZIONE DEGLI AVENTI DIRITTO

        // caricamento delle public key dei votanti su portale
        for(Voter v: voters){
            v.postPublicKey(votingPortal);
        }

        System.out.println("[T0] Users registered to vote!");

        // caricamento delle chiavi pubbliche dei votanti dal portale alla blockchain

        List<BigInteger> votersPublicKeyList = new ArrayList<>(voterNumber);

        try (BufferedReader br = new BufferedReader(new FileReader(votingPortal))) {
            for(String line; (line = br.readLine()) != null; ) {
                votersPublicKeyList.add(new BigInteger(line));
            }
        }

        //transazioni contenenti le public key dei votanti, firmate congiuntamente da autorità

        pk_Sig = authoritiesCreateJointSignature(authoritiesInvolvedInVote, authorities, pkSigAj, votersPublicKeyList.toString());
        SchnorrSig votersListjointSig = pk_Sig.u;
        SchnorrPK  votersListjointpk = pk_Sig.t;

        blockchain.insertPKTransactions(votersListjointpk,votersListjointSig,votersPublicKeyList);

        System.out.println("\t Subscribed voters' PKs published by authorities!");

        // FASE DI VOTAZIONE

        // pubblicazione transazione t_votestart, firmata congiuntamente da autorità
        String inizioVotazioneMsg = "inizio votazione";

        pk_Sig = authoritiesCreateJointSignature(authoritiesInvolvedInVote, authorities, pkSigAj, inizioVotazioneMsg);
        SchnorrSig startvotejointSig = pk_Sig.u;
        SchnorrPK  startvotejointpk = pk_Sig.t;

        blockchain.insertStartTransaction(startvotejointpk,startvotejointSig, inizioVotazioneMsg);

        System.out.println("[T1] Start vote transaction added!\n");

        BigInteger vote;
        //avvio della votazione, ogni votante ammesso vota una volta
        for(int i=0; i<voterNumber; i++){
            vote = voters.get(i).vote(blockchain,pkA);
            System.out.println("\t\tVoter with pkSig " + voters.get(i).getPKSig().getH() + " voted for " + vote);
        }

        //simuliamo un voto scorretto perché non passano più almeno 500ms dall'ultimo voto dello stesso votante
        Thread.sleep(1000);
        vote = voters.get(0).vote(blockchain,pkA); //vote added
        System.out.println("\t\tVoter with pkSig " + voters.get(0).getPKSig().getH() + " voted for " + vote);
        voters.get(0).vote(blockchain,pkA); //vote not added
        System.out.println("\t\tVoter with pkSig " + voters.get(0).getPKSig().getH() + " tried to vote for " + vote);

        // aggiunta della transazione t_voteEnd da parte delle autorità
        String fineVotazioneMsg = "fine votazione";

        pk_Sig = authoritiesCreateJointSignature(authoritiesInvolvedInVote, authorities, pkSigAj, fineVotazioneMsg);
        SchnorrSig endvotejointSig = pk_Sig.u;
        SchnorrPK  endvotejointpk = pk_Sig.t;

        blockchain.insertStopTransaction(endvotejointpk,endvotejointSig, fineVotazioneMsg);

        System.out.println("\n[T2] End vote transaction added!");

        // CONTEGGIO

        ElGamalCT totalvotesOfOne;

        totalvotesOfOne = blockchain.countVotes(pkA);

        System.out.println("\t Votes filtered and counted!");

        // le autorità singolarmente pubblicano i propri wj sulla blockchain

        for(Authority authority: authorities){
           authority.publishDecryptionContribute(pkA,totalvotesOfOne, blockchain);
        }

        System.out.println("\t Authorities published threshold decryption contributes!");

        // chiunque ora puo decifrare, essendo tutto noto e pubblico;

        // DECIFRATURA

        // ottenimento del ciphertext dei voti validi non duplicati nell'intervallo [t_votestart,t_voteend]
        ElGamalCT totalciphertext = blockchain.countVotes(pkA);

        // ottenimento contributi di decifratura parziali delle autorità
        BigInteger[] W = blockchain.getAuthorityDecryptContributes();

        // decifratura del ciphertext mediante i contributi
        BigInteger decripted = Decrypt(pkA,totalciphertext, W);

        // ricerca esaustiva per ottenere il numero di preferenze associate al candidato 1
        BigInteger votesTo1 = blockchain.bruteforceGetVotesTo1(decripted, pkA.params.g, pkA.params.p, BigInteger.valueOf(voterNumber + 1));

        System.out.println("\t Votes of ones decrypted and bruteforced!");

        // PUBBLICAZIONE DEL RISULTATO

        // messaggio contenente esito della votazione
        String resultsOfVotingMessage = "voti assegnati a candidato 0 = " + (voterNumber - votesTo1.intValue()) + ", voti assegnati a candidato 1 = " + votesTo1;

        pk_Sig = authoritiesCreateJointSignature(authoritiesInvolvedInVote, authorities, pkSigAj, resultsOfVotingMessage);
        SchnorrSig resultsOfVotingSig = pk_Sig.u;
        SchnorrPK  resultsOfVotingPkSig = pk_Sig.t;

        // inserimento su blockchain dell'esito della votazione firmato dalle autorità
        blockchain.insertSignedTransaction(resultsOfVotingPkSig,resultsOfVotingSig, resultsOfVotingMessage);

        System.out.println("\t Voting results transaction added!");

    }

}
