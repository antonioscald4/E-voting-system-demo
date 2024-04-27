package crypto.utils.Schnorr;

import java.math.BigInteger;

public class SchnorrSig{
	BigInteger a,e,z;

	public SchnorrSig(BigInteger a,BigInteger e,BigInteger z) {
		this.a=a;
		this.e=e;
		this.z=z;
	}

	@Override
	public String toString() {
		return "SchnorrSig{" +
				"a=" + a +
				", e=" + e +
				", z=" + z +
				'}';
	}

}