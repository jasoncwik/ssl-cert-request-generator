package org.cwik.reqgen;

import java.io.*;
import java.security.KeyPair;
import java.security.Provider;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.pqc.math.linearalgebra.Vector;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

/**
 * Created by cwikj on 3/12/16.
 */
public class CertificateRequest {
    public static final String PEM_DESC_RSA_PRIV_KEY = "RSA PRIVATE KEY";
    public static final String PEM_DESC_CERT_REQ = "CERTIFICATE REQUEST";

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

        X500NameBuilder xb = new X500NameBuilder()
                .addRDN(BCStyle.C, country)
                .addRDN(BCStyle.ST, stateOrProvence)
                .addRDN(BCStyle.L, locality)
                .addRDN(BCStyle.O, organization)
                .addRDN(BCStyle.OU, organizationalUnit)
                .addRDN(BCStyle.CN, subject);
        if(emailAddress != null) {
            xb.addRDN(BCStyle.EmailAddress, emailAddress);
        }

        List<GeneralName> sans = new ArrayList<GeneralName>();
        if(dnsSubjectAlternativeNames != null) {
            for(String dnsName : dnsSubjectAlternativeNames) {
                sans.add(new GeneralName(GeneralName.dNSName, dnsName));
            }
        }
        if(ipSubjectAlternativeNames != null) {
            for(String ipAddr : ipSubjectAlternativeNames) {
                sans.add(new GeneralName(GeneralName.iPAddress, ipAddr));
            }
        }

        PKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(xb.build(), siginingKey.getPublic());

        // Add Subject Alternative Names
        if(sans.size() > 0) {
            GeneralNamesBuilder gnb = new GeneralNamesBuilder();
            for(GeneralName n : sans) {
                gnb.addName(n);
            }

            Extension san;
            try {
                san = new Extension(Extension.subjectAlternativeName, false, new DEROctetString(gnb.build()));
            } catch (IOException e) {
                throw new RuntimeException("Could not encode SAN attribute");
            }
            Extensions extensions = new Extensions(san);

            builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest,
                    extensions);
        }

        return builder.build(signer);
    }

    /**
     * Make the certificate request into PEM-encoded text.
     */
    public static byte[] getPEMEncoded(PKCS10CertificationRequest request) throws IOException {
        PemObject po = new PemObject(PEM_DESC_CERT_REQ, request.getEncoded());
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        PemWriter pemWriter = new PemWriter(new OutputStreamWriter(baos));
        pemWriter.writeObject(po);
        pemWriter.close();
        return baos.toByteArray();
    }

    /**
     * Writes the given data to a file in PEM format
     * @param data the data to write
     * @param description the PEM file description, e.g. "RSA PRIVATE KEY"
     * @param file the file to output the PEM data to
     * @throws Exception if an error occurs writing the data
     */
    public static void writePemFile(byte[] data, String description, File file) throws Exception {
        PemObject po = new PemObject(description, data);
        PemWriter pemWriter = new PemWriter(new FileWriter(file));
        pemWriter.writeObject(po);
        pemWriter.close();
    }
}
