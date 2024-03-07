package com.github.rodrigofcr.xmlsigner;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

@Service
public class SigningService {

    @Value("${certificate.file.path}")
    private String certificatePath;
    @Value("${certificate.file.alias}")
    private String certificateAlias;
    @Value("${certificate.file.password}")
    private String certificatePassword;

    public String signWithPKCS12Certificate(
            final String xmlString) {
        try {
            //Reference documentation:
            //https://www.czetsuyatech.com/2023/02/java-implementation-of-digital-signature-and-x509certificate.html
            //https://www.guj.com.br/t/assinar-xml-com-certificado-digital/354465

            //Fix transform bug
//            System.setProperty("javax.xml.transform.TransformerFactory", "com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl");

            //Create a DOM XMLSignatureFactory that will be used to generate the
            //enveloped signature.
            final XMLSignatureFactory xmlSignatureFactory = XMLSignatureFactory.getInstance("DOM");

            //Create a Reference to the enveloped document (in this case, you
            //are signing the whole document, so a URI of "" signifies that,
            //and also specify the SHA1 digest algorithm and the ENVELOPED Transform.
            final Reference reference = xmlSignatureFactory.newReference(
                    "",
                    xmlSignatureFactory.newDigestMethod(DigestMethod.SHA1, null),
                    Collections.singletonList(xmlSignatureFactory.newTransform(
                            Transform.ENVELOPED, (TransformParameterSpec) null)),
                    null,
                    null);

            //Create the SignedInfo.
            final SignedInfo signedInfo = xmlSignatureFactory.newSignedInfo(
                    xmlSignatureFactory.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE,
                            (C14NMethodParameterSpec) null),
                    xmlSignatureFactory.newSignatureMethod(SignatureMethod.RSA_SHA1, null),
                    Collections.singletonList(reference));

            //Load the KeyStore and get the signing key and certificate.
            final KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(new FileInputStream(certificatePath), certificatePassword.toCharArray());
            final KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(
                    certificateAlias, new KeyStore.PasswordProtection(certificatePassword.toCharArray()));
            final X509Certificate x509Certificate = (X509Certificate) privateKeyEntry.getCertificate();

            //Create the KeyInfo containing the X509Data.
            final KeyInfoFactory keyInfoFactory = xmlSignatureFactory.getKeyInfoFactory();
            final List x509Content = new ArrayList();
            x509Content.add(x509Certificate.getSubjectX500Principal().getName());
            x509Content.add(x509Certificate);
            final X509Data x509Data = keyInfoFactory.newX509Data(x509Content);
            final KeyInfo keyInfo = keyInfoFactory.newKeyInfo(Collections.singletonList(x509Data));

            //Instantiate the document to be signed.
            final DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
            documentBuilderFactory.setNamespaceAware(true);
            final Document document = documentBuilderFactory.newDocumentBuilder()
                    .parse(new InputSource(new StringReader(xmlString)));

            //Create a DOMSignContext and specify the RSA PrivateKey and
            //location of the resulting XMLSignature's parent element.
            final DOMSignContext domSignContext = new DOMSignContext(
                    privateKeyEntry.getPrivateKey(), document.getDocumentElement());

            //Create the XMLSignature, but don't sign it yet.
            final XMLSignature xmlSignature = xmlSignatureFactory.newXMLSignature(signedInfo, keyInfo);

            //Marshal, generate, and sign the enveloped signature.
            xmlSignature.sign(domSignContext);

            // Output the resulting document as xml string
            final StringWriter stringWriter = new StringWriter();
            final Transformer transformer = TransformerFactory.newInstance().newTransformer();
            transformer.transform(
                    new DOMSource(document),
                    new StreamResult(stringWriter));

            return stringWriter.toString();

        } catch (final NoSuchAlgorithmException | ParserConfigurationException | SAXException |
                       KeyStoreException | CertificateException | UnrecoverableEntryException |
                       InvalidAlgorithmParameterException | MarshalException |
                       XMLSignatureException | IOException | TransformerException exception) {
            throw new RuntimeException(exception);
        }
    }

}
