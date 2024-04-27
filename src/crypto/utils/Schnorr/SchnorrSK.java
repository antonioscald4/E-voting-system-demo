package crypto.utils.Schnorr;

import java.math.BigInteger;

public class SchnorrSK{
	private final BigInteger s;
	private final SchnorrPK PK;

	public SchnorrSK(BigInteger s,SchnorrPK PK) {
		this.s=s;
		this.PK=PK;
	}

	public BigInteger getS() {
		return s;
	}

	public SchnorrPK getPK() {
		return PK;
	}

	@Override
	public String toString() {
		return "SchnorrSK{" +
				"s=" + s +
				", PK=" + PK +
				'}';
	}
}