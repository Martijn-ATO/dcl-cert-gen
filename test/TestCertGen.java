import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.util.Properties;

import org.junit.jupiter.api.Test;

class TestCertGen {

	@Test
	void test() {
		try {
			Properties props = System.getProperties();
			String path = props.getProperty("user.dir");
			String fs = props.getProperty("file.separator");
			String keyFile = String.join(fs, path, "Digital_Capability_Locator_Authority.key");
			X509Certificate cert = au.gov.ato.dcl.test.CertGen.apply("CN=test", keyFile);
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
			Properties props = System.getProperties();
			String path = props.getProperty("user.dir");
			String fs = props.getProperty("file.separator");
			String keyFile = String.join(fs, path, "Digital_Capability_Locator_Authority.key");
			String chain = au.gov.ato.dcl.test.CertGen.certChain("CN=test", keyFile);
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
