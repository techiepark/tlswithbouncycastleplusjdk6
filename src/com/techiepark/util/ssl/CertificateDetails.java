package com.techiepark.util.ssl;

/**
 * 
 * @author techiepark
 *
 */
public class CertificateDetails {
	
	private int keySize = 1024;
	private String commonName = "commonName";
	private String organizationalUnit = "organizationalUnit";
	private String organization = "organization";
	private String city = "city";
	private String state = "state";
	private String country = "country";
	private String alias = "alias";
	private String password = "564321";
	private int validity = 365 * 100; // 100 years
	private String keyPairGeneratorAlgorithm = "RSA";
	private String signatureAlgorithm = "SHA1WithRSA";

	public CertificateDetails(int keySize, String commonName, String organizationalUnit, String organization, String city, String state,
			String country, String alias, String password, int validity, String keyPairGeneratorAlgorithm, String signatureAlgorithm) {
		super();
		this.keySize = keySize;
		this.commonName = commonName;
		this.organizationalUnit = organizationalUnit;
		this.organization = organization;
		this.city = city;
		this.state = state;
		this.country = country;
		this.alias = alias;
		this.password = password;
		this.validity = validity;
		this.keyPairGeneratorAlgorithm = keyPairGeneratorAlgorithm;
		this.signatureAlgorithm = signatureAlgorithm;
	}

	public CertificateDetails() {
	}

	public String getAlias() {
		return alias;
	}
	
	public void setAlias(String alias) {
		this.alias = alias;
	}
	
	public String getCity() {
		return city;
	}
	
	public void setCity(String city) {
		this.city = city;
	}
	
	public String getCommonName() {
		return commonName;
	}
	
	public void setCommonName(String commonName) {
		this.commonName = commonName;
	}
	
	public String getCountry() {
		return country;
	}
	
	public void setCountry(String country) {
		this.country = country;
	}
	
	public int getKeySize() {
		return keySize;
	}
	
	public void setKeySize(int keySize) {
		this.keySize = keySize;
	}
	
	public String getOrganization() {
		return organization;
	}
	
	public void setOrganization(String organization) {
		this.organization = organization;
	}
	
	public String getOrganizationalUnit() {
		return organizationalUnit;
	}
	
	public void setOrganizationalUnit(String organizationalUnit) {
		this.organizationalUnit = organizationalUnit;
	}
	
	public String getPassword() {
		return password;
	}
	
	public void setPassword(String password) {
		this.password = password;
	}
	
	public String getState() {
		return state;
	}
	
	public void setState(String state) {
		this.state = state;
	}

	public int getValidity() {
		return validity;
	}

	public void setValidity(int validity) {
		this.validity = validity;
	}

	public String getKeyPairGeneratorAlgorithm() {
		return keyPairGeneratorAlgorithm;
	}

	public void setKeyPairGeneratorAlgorithm(String keyPairGeneratorAlgorithm) {
		this.keyPairGeneratorAlgorithm = keyPairGeneratorAlgorithm;
	}

	public String getSignatureAlgorithm() {
		return signatureAlgorithm;
	}

	public void setSignatureAlgorithm(String signatureAlgorithm) {
		this.signatureAlgorithm = signatureAlgorithm;
	}
}
