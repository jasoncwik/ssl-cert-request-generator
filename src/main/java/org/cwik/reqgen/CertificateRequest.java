package org.cwik.reqgen;

import java.io.IOException;
import java.security.KeyPair;
import java.security.Provider;
import java.util.List;

import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.encoders.Base64;

/**
 * Created by cwikj on 3/12/16.
 */
public class CertificateRequest {
    private KeyPair siginingKey;
    private String subject;
    private List<String> ipSubjectAlternativeNames;
    private List<String> dnsSubjectAlternativeNames;
    private String country;
    private String stateOrProvence;
    private String locality;
    private String organization;
    private String organizationalUnit;
    private String emailAddress;
    private String algorithm = "SHA1WithRSAEncryption";


    public List<String> getIpSubjectAlternativeNames() {
        return ipSubjectAlternativeNames;
    }

    public void setIpSubjectAlternativeNames(List<String> ipSubjectAlternativeNames) {
        this.ipSubjectAlternativeNames = ipSubjectAlternativeNames;
    }

    public String getSubject() {
        return subject;
    }

    public void setSubject(String subject) {
        this.subject = subject;
    }

    public KeyPair getSiginingKey() {
        return siginingKey;
    }

    public void setSiginingKey(KeyPair siginingKey) {
        this.siginingKey = siginingKey;
    }

    public List<String> getDnsSubjectAlternativeNames() {
        return dnsSubjectAlternativeNames;
    }

    public void setDnsSubjectAlternativeNames(List<String> dnsSubjectAlternativeNames) {
        this.dnsSubjectAlternativeNames = dnsSubjectAlternativeNames;
    }

    public String getCountry() {
        return country;
    }

    public void setCountry(String country) {
        this.country = country;
    }

    public String getStateOrProvence() {
        return stateOrProvence;
    }

    public void setStateOrProvence(String stateOrProvence) {
        this.stateOrProvence = stateOrProvence;
    }

    public String getLocality() {
        return locality;
    }

    public void setLocality(String locality) {
        this.locality = locality;
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


    public String getEmailAddress() {
        return emailAddress;
    }

    public void setEmailAddress(String emailAddress) {
        this.emailAddress = emailAddress;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }


    public PKCS10CertificationRequest generateRequest() {
        ContentSigner signer = null;
        try {
            signer = new JcaContentSignerBuilder(algorithm).build(siginingKey.getPrivate());
        } catch (OperatorCreationException e) {
            throw new RuntimeException("Could not construct content signer.", e);
        }

        X500NameBuilder xb = new X500NameBuilder().addRDN(BCStyle.CN, subject)
                .addRDN(BCStyle.C, country)
                .addRDN(BCStyle.L, locality)
                .addRDN(BCStyle.ST, stateOrProvence)
                .addRDN(BCStyle.O, organization)
                .addRDN(BCStyle.OU, organizationalUnit);
        if(emailAddress != null) {
            xb.addRDN(BCStyle.EmailAddress, emailAddress);
        }

        PKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(xb.build(), siginingKey.getPublic());
        return builder.build(signer);
    }

    public static String getPEMEncoded(PKCS10CertificationRequest request) {
        byte[] b64 = new byte[0];
        try {
            b64 = Base64.encode(request.getEncoded());
        } catch (IOException e) {
            throw new RuntimeException("Failed to encode Base64 data", e);
        }
        StringBuilder sb = new StringBuilder();
        sb.append("-----BEGIN CERTIFICATE REQUEST-----\n");
        String s = new String(b64);
        // Break into 64 character lines.
        for(int i=0; i<s.length(); i+=64) {
            int last = i+64;
            if(last > s.length()) {
                last = s.length();
            }
            sb.append(s.substring(i, last));
            sb.append("\n");
        }
        sb.append("-----END CERTIFICATE REQUEST-----\n");
        return sb.toString();
    }
}
