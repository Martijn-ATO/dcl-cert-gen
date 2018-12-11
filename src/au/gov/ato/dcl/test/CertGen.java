package au.gov.ato.dcl.test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Date;

import javax.xml.bind.DatatypeConverter;

import sun.misc.BASE64Decoder;
import sun.security.x509.AlgorithmId;
import sun.security.x509.CertificateAlgorithmId;
import sun.security.x509.CertificateIssuerName;
import sun.security.x509.CertificateSerialNumber;
import sun.security.x509.CertificateValidity;
import sun.security.x509.CertificateVersion;
import sun.security.x509.CertificateX509Key;
import sun.security.x509.X500Name;
import sun.security.x509.X509CertImpl;
import sun.security.x509.X509CertInfo;

public class CertGen {

	public static String certChain(String dn) throws GeneralSecurityException, IOException {
		return CertGen.caCertPEM().concat(CertGen.certToString(CertGen.apply(dn)));
	}

	public static X509Certificate apply(String dn) throws GeneralSecurityException, IOException {
		final KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(1024);
		final KeyPair keypair = keyGen.generateKeyPair();
		// PrivateKey privKey = keypair.getPrivate();
		// PublicKey pubKey = keypair.getPublic();
		final PrivateKey caKey = CertGen.getCaKeyFromString(CertGen.caKeyPEM());
		final Certificate caCert = CertGen.getCACertFromString(CertGen.caCertPEM());
		return generateCertificate(dn, keypair, 365, "SHA1withRSA", caKey, caCert);
	}

	/**
	 * Read the CA private key from bundle
	 * 
	 * @return base64 encoded CA private key
	 */
	private static String caKeyPEM() {
		final InputStream in = new CertGen().getClass()
				.getResourceAsStream("/resources/Digital_Capability_Locator_Authority.key");
		final java.util.Scanner scanner = new java.util.Scanner(in);
		final java.util.Scanner s = scanner.useDelimiter("\\A");
		final String keyPEM = s.hasNext() ? s.next() : "";
		scanner.close();
		return keyPEM;
	}

	/**
	 * Read the CA public certificate from bundle
	 * 
	 * @return base64 encoded CA public key
	 */
	public static String caCertPEM() {
		final InputStream in = new CertGen().getClass()
				.getResourceAsStream("/resources/Digital_Capability_Locator_Authority.crt");
		final java.util.Scanner scanner = new java.util.Scanner(in);
		final java.util.Scanner s = scanner.useDelimiter("\\A");
		final String certPEM = s.hasNext() ? s.next() : "";
		scanner.close();
		return certPEM;
	}

	/**
	 * Generate a private key object from a base64 encoded string
	 * 
	 * @param key
	 * @return
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeySpecException
	 */
	private static PrivateKey getCaKeyFromString(String key)
			throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		final String privKeyPEM = key.replace("-----BEGIN PRIVATE KEY-----", "").replace("-----END PRIVATE KEY-----",
				"");

		final BASE64Decoder b64 = new BASE64Decoder();
		final byte[] decoded = b64.decodeBuffer(privKeyPEM);

		final PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decoded);
		final KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePrivate(spec);
	}

	/**
	 * Generate a public key from a base64 encoded string
	 * 
	 * @param key
	 * @return
	 * @throws IOException
	 * @throws GeneralSecurityException
	 */
	private static PublicKey getPublicKeyFromString(String key) throws IOException, GeneralSecurityException {
		final String pubKeyPEM = key.replace("-----BEGIN PUBLIC KEY-----\n", "").replace("-----END PUBLIC KEY-----",
				"");

		final BASE64Decoder b64 = new BASE64Decoder();
		final byte[] decoded = b64.decodeBuffer(pubKeyPEM);

		final PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decoded);
		final KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePublic(spec);
	}

	private static Certificate getCACertFromString(String cert) throws CertificateException {
		final CertificateFactory cf = CertificateFactory.getInstance("X.509");
		return cf.generateCertificate(new ByteArrayInputStream(cert.getBytes()));
	}

	/**
	 * Create a self-signed X.509 Certificate
	 * 
	 * @param dn        the X.509 Distinguished Name, eg "CN=Test, L=London, C=GB"
	 * @param pair      the KeyPair
	 * @param days      how many days from now the Certificate is valid for
	 * @param algorithm the signing algorithm, eg "SHA1withRSA"
	 */
	private static X509Certificate generateCertificate(String dn, KeyPair pair, int days, String algorithm,
			PrivateKey caKey, Certificate caCert) throws GeneralSecurityException, IOException {
		final PrivateKey privkey = pair.getPrivate();
		final X509CertInfo info = new X509CertInfo();
		final Date from = new Date();
		final Date to = new Date(from.getTime() + days * 86400000l);
		final CertificateValidity interval = new CertificateValidity(from, to);
		final BigInteger sn = new BigInteger(64, new SecureRandom());
		final X500Name owner = new X500Name(dn);

		Signature signature;
		try {
			signature = Signature.getInstance(algorithm);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
		signature.initSign(caKey);

		final byte[] encoded = caCert.getEncoded();
		final X509CertImpl caCertImpl = new X509CertImpl(encoded);

		final X509CertInfo caCertInfo = (X509CertInfo) caCertImpl.get(X509CertImpl.NAME + "." + X509CertImpl.INFO);

		final X500Name issuer = (X500Name) caCertInfo.get(X509CertInfo.SUBJECT + "." + CertificateIssuerName.DN_NAME);

		info.set(X509CertInfo.VALIDITY, interval);
		info.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(sn));
		info.set(X509CertInfo.SUBJECT, owner);
		info.set(X509CertInfo.ISSUER, issuer);
		info.set(X509CertInfo.KEY, new CertificateX509Key(pair.getPublic()));
		info.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));
		AlgorithmId algo = new AlgorithmId(AlgorithmId.sha1WithRSAEncryption_oid);
		info.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(algo));

		// Sign the cert to identify the algorithm that's used.
		X509CertImpl cert = new X509CertImpl(info);
		cert.sign(privkey, algorithm);

		// Update the algorith, and resign.
		algo = (AlgorithmId) cert.get(X509CertImpl.SIG_ALG);
		info.set(CertificateAlgorithmId.NAME + "." + CertificateAlgorithmId.ALGORITHM, algo);
		cert = new X509CertImpl(info);
		cert.sign(privkey, algorithm);
		return cert;
	}

	private static String certToString(X509Certificate cert) {
		final StringWriter sw = new StringWriter();
		try {
			sw.write("-----BEGIN CERTIFICATE-----\n");
			sw.write(DatatypeConverter.printBase64Binary(cert.getEncoded()).replaceAll("(.{64})", "$1\n"));
			sw.write("\n-----END CERTIFICATE-----\n");
		} catch (CertificateEncodingException e) {
			e.printStackTrace();
		}
		return sw.toString();
	}
}
