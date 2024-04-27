package crypto.utils.Schnorr;

import java.math.BigInteger;

public class SchnorrPK{
	BigInteger g,h,p,q;
	int securityparameter;

	public SchnorrPK(BigInteger p,BigInteger q,BigInteger g,BigInteger h,int securityparameter) {
		this.p=p;
		this.q=q;
		this.g=g;
		this.h=h;
		this.securityparameter=securityparameter;
	}

	public BigInteger getG() {
		return g;
	}

	public BigInteger getH() {
		return h;
	}

	public BigInteger getP() {
		return p;
	}

	public BigInteger getQ() {
		return q;
	}

	public int getSecurityparameter() {
		return securityparameter;
	}

	@Override
	public String toString() {
		return "SchnorrPK{" +
				"g=" + g +
				", h=" + h +
				", p=" + p +
				", q=" + q +
				", securityparameter=" + securityparameter +
				'}';
	}
}