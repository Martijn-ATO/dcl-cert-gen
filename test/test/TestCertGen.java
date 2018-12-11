package test;

import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import org.junit.jupiter.api.Test;

class TestCertGen {

	@Test
	void test() {
		try {
			X509Certificate cert = au.gov.ato.dcl.test.CertGen.apply("CN=test");
			assertEquals("Issuer DN equals", "CN=Digital Capability Locator Authority", cert.getIssuerDN().getName());
			assertEquals("Subject DN equals", "CN=test", cert.getSubjectDN().getName());		
		} catch (GeneralSecurityException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	@Test
	void test2() {
		try {
			String chain = au.gov.ato.dcl.test.CertGen.certChain("CN=test");
			System.err.println(chain);
		} catch (GeneralSecurityException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

}
