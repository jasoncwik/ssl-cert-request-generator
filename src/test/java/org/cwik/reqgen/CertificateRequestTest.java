package org.cwik.reqgen;

import junit.framework.TestCase;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.security.*;

/**
 * Created by cwikj on 3/12/16.
 */
public class CertificateRequestTest extends TestCase {

    public void testGenerateRequest() throws Exception {
        String algorithm = "SHA256withRSA";

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair kp = keyPairGenerator.generateKeyPair();


        CertificateRequest req = new CertificateRequest();
        req.setSubject("*.example.com");
        req.setCountry("US");
        req.setStateOrProvence("Minnesota");
        req.setLocality("Minneapolis");
        req.setOrganization("cwik.org");
        req.setOrganizationalUnit("Developer Ninjas");
        req.setSiginingKey(kp);
        req.setAlgorithm(algorithm);

        PKCS10CertificationRequest request = req.generateRequest();

        System.out.println(CertificateRequest.getPEMEncoded(request));

        assertEquals(0, request.getAttributes().length);

    }
}