package au.gov.ato.dcl.test;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.Vector;

import sun.misc.BASE64Decoder;
import sun.security.util.ObjectIdentifier;
import sun.security.x509.AlgorithmId;
import sun.security.x509.AuthorityKeyIdentifierExtension;
import sun.security.x509.CertificateAlgorithmId;
import sun.security.x509.CertificateExtensions;
import sun.security.x509.CertificateIssuerName;
import sun.security.x509.CertificateSerialNumber;
import sun.security.x509.CertificateValidity;
import sun.security.x509.CertificateVersion;
import sun.security.x509.CertificateX509Key;
import sun.security.x509.ExtendedKeyUsageExtension;
import sun.security.x509.KeyIdentifier;
import sun.security.x509.KeyUsageExtension;
import sun.security.x509.SubjectKeyIdentifierExtension;
import sun.security.x509.X500Name;
import sun.security.x509.X509CertImpl;
import sun.security.x509.X509CertInfo;

public class CertGen {

	public static String base64CertChain(String dn, String privKeyPath, String pubKeyPath) throws GeneralSecurityException, IOException {
		final String LINE_SEPARATOR = System.getProperty("line.separator");
//		final Base64.Encoder encoder = Base64.getMimeEncoder(64, LINE_SEPARATOR.getBytes());
		final Base64.Encoder encoder = Base64.getEncoder();
		byte[] encoded = encoder.encode(CertGen.certChain(dn, privKeyPath, pubKeyPath).getBytes());
		return new String(encoded);
	}
	
	public static String certChain(String dn, String privKeyPath, String pubKeyPath) throws GeneralSecurityException, IOException {
		return String.join("", CertGen.caCertPEM(pubKeyPath), CertGen.certToString(CertGen.apply(dn, privKeyPath, pubKeyPath)));
	}

	public static X509Certificate apply(String dn, String privKeyPath, String pubKeyPath) throws GeneralSecurityException, IOException {
		final KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(2048);
		final KeyPair keypair = keyGen.generateKeyPair();
		// PrivateKey privKey = keypair.getPrivate();
		// PublicKey pubKey = keypair.getPublic();
		final PrivateKey caKey = CertGen.getCaKeyFromString(CertGen.caKeyPEM(privKeyPath));
		final Certificate caCert = CertGen.getCACertFromString(CertGen.caCertPEM(pubKeyPath));
		return generateCertificate(dn, keypair, 365, "SHA256withRSA", caKey, caCert);
	}

	/**
	 * Read the CA private key from bundle
	 * 
	 * @return base64 encoded CA private key
	 * @throws FileNotFoundException 
	 */
	private static String caKeyPEM(String privKeyPath) throws FileNotFoundException {
		final InputStream in = new FileInputStream(privKeyPath);
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
	 * @throws FileNotFoundException 
	 */
	public static String caCertPEM(String pubKeyPath) throws FileNotFoundException {
		final InputStream in = new FileInputStream(pubKeyPath);
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
		final X500Name subject = new X500Name(dn);

		final byte[] encoded = caCert.getEncoded();
		final X509CertImpl caCertImpl = new X509CertImpl(encoded);

		final X509CertInfo caCertInfo = (X509CertInfo) caCertImpl.get(X509CertImpl.NAME + "." + X509CertImpl.INFO);

		final X500Name issuer = (X500Name) caCertInfo.get(X509CertInfo.SUBJECT + "." + CertificateIssuerName.DN_NAME);
		CertificateExtensions exts = new CertificateExtensions();
		
		// Extensions[6]: X509v3 Key Usage
        KeyUsageExtension keyUsage = new KeyUsageExtension();
        keyUsage.set(KeyUsageExtension.DIGITAL_SIGNATURE, Boolean.TRUE);
        keyUsage.set(KeyUsageExtension.NON_REPUDIATION, Boolean.FALSE);
        keyUsage.set(KeyUsageExtension.KEY_ENCIPHERMENT, Boolean.TRUE);
        keyUsage.set(KeyUsageExtension.DATA_ENCIPHERMENT, Boolean.TRUE);
        keyUsage.set(KeyUsageExtension.KEY_AGREEMENT, Boolean.TRUE);
        keyUsage.set(KeyUsageExtension.KEY_CERTSIGN, Boolean.FALSE);
        keyUsage.set(KeyUsageExtension.CRL_SIGN, Boolean.FALSE);
        keyUsage.set(KeyUsageExtension.ENCIPHER_ONLY, Boolean.FALSE);
        keyUsage.set(KeyUsageExtension.DECIPHER_ONLY, Boolean.FALSE);
        exts.set(KeyUsageExtension.NAME, keyUsage);
        
	     // Extensions[5]: X509v3 Extended Key Usage
		Vector<ObjectIdentifier> keyUsages = new Vector<>();
       	// OID defined in RFC 3280 Sections 4.2.1.13
       	// more from http://www.alvestrand.no/objectid/1.3.6.1.5.5.7.3.html
       	// serverAuth
       	keyUsages.addElement(ObjectIdentifier.newInternal(new int[] { 1, 3, 6, 1, 5, 5, 7, 3, 1 }));
       	// clientAuth
       	keyUsages.addElement(ObjectIdentifier.newInternal(new int[] { 1, 3, 6, 1, 5, 5, 7, 3, 2 }));
       	exts.set(ExtendedKeyUsageExtension.NAME, new ExtendedKeyUsageExtension(keyUsages));
 
		  // Extensions[8]: X509v3 Subject Key Identifier
        exts.set(SubjectKeyIdentifierExtension.NAME,
                new SubjectKeyIdentifierExtension(new KeyIdentifier(pair.getPublic()).getIdentifier()));

        // Extensions[2]: X509v3 Authority Key Identifier
        exts.set(AuthorityKeyIdentifierExtension.NAME,
                new AuthorityKeyIdentifierExtension(new KeyIdentifier(caCert.getPublicKey()),
                        null, null));

//        exts.set(AuthorityKeyIdentifierExtension.NAME,
//                new AuthorityKeyIdentifierExtension(new KeyIdentifier(caCert.getPublicKey()),
//                        new GeneralNames().add(new GeneralName(subject)), new SerialNumber(1)));
 
		info.set(X509CertInfo.VALIDITY, interval);
		info.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(sn));
		info.set(X509CertInfo.SUBJECT, subject);
		info.set(X509CertInfo.ISSUER, issuer);
		info.set(X509CertInfo.KEY, new CertificateX509Key(pair.getPublic()));
		info.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));
		AlgorithmId algo = new AlgorithmId(AlgorithmId.sha256WithRSAEncryption_oid);
		info.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(algo));

		info.set(X509CertInfo.EXTENSIONS, exts);

		// Sign the cert to identify the algorithm that's used.
		X509CertImpl cert = new X509CertImpl(info);
		cert.sign(privkey, algorithm);

		// Update the algorith, and resign.
		algo = (AlgorithmId) cert.get(X509CertImpl.SIG_ALG);
		info.set(CertificateAlgorithmId.NAME + "." + CertificateAlgorithmId.ALGORITHM, algo);
		cert = new X509CertImpl(info);
		cert.sign(caKey, algorithm);
		return cert;
	}

	public static String certToString(X509Certificate cert) throws CertificateEncodingException {
		final String BEGIN_CERT = "-----BEGIN CERTIFICATE-----";
		final String END_CERT = "-----END CERTIFICATE-----";
		final String LINE_SEPARATOR = System.getProperty("line.separator");
		final Base64.Encoder encoder = Base64.getMimeEncoder(64, LINE_SEPARATOR.getBytes());
	    final String encodedCertText = new String(encoder.encode(cert.getEncoded()));
	    return String.join(LINE_SEPARATOR, BEGIN_CERT, encodedCertText, END_CERT);
	}
}
