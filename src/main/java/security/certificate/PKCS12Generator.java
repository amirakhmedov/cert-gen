package security.certificate;

import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX500NameUtil;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import javax.security.auth.x500.X500Principal;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;

/**
 * PKCS12Generator class is used to generate self-signed PKCS#12 file. This class uses BouncyCastle API.
 *
 * @author <a href="mailto:amir.akhmedov@gmail.com">Amir Akhmedov</a>
 */
public class PKCS12Generator {

    private static final String BC = BouncyCastleProvider.PROVIDER_NAME;

    private int keySize = 1024;
    private PrivateKey caPrivate;
    private X509Certificate caCert;

    public PKCS12Generator(PrivateKey caPrivate, X509Certificate caCert) {
        Security.addProvider(new BouncyCastleProvider());

        this.caPrivate = caPrivate;
        this.caCert = caCert;
    }

    /**
     * Generates self-signed PKCS#12 file
     *
     * @param subjectCN subject's CN. e.g.: "CN=Requested Certificate"
     * @param serial generated certificate's serial number
     * @param keyAlias generated certificate's alias
     * @param validFrom generated certificate's validFrom
     * @param validTo generated certificate's validTo
     * @param keyPassword generated PKCS#12 protection password
     * @param outputStream OutputStream to write PKCS#12 file
     * @throws NoSuchProviderException
     * @throws NoSuchAlgorithmException
     * @throws UnrecoverableKeyException
     * @throws KeyStoreException
     * @throws OperatorCreationException
     * @throws CertificateException
     * @throws SignatureException
     * @throws InvalidKeyException
     * @throws IOException
     */
    public void generate(String subjectCN, BigInteger serial, String keyAlias, Date validFrom, Date validTo,
                         char[] keyPassword, OutputStream outputStream)
            throws NoSuchProviderException, NoSuchAlgorithmException,
            UnrecoverableKeyException, KeyStoreException,
            OperatorCreationException, CertificateException,
            SignatureException, InvalidKeyException, IOException, PKCSException {

        KeyPair keyPair = generateKeyPair(keySize);

        PKCS10CertificationRequestBuilder certReqBuilder =
                new JcaPKCS10CertificationRequestBuilder(new X500Principal(subjectCN), keyPair.getPublic());
        JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder("SHA256withRSA");
        ContentSigner signer = csBuilder.build(keyPair.getPrivate());
        PKCS10CertificationRequest csr = certReqBuilder.build(signer);

        if(!csr.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider(BC).build(keyPair.getPublic())))
            throw new PKCSException("Signature is invalid.");

        X509Certificate clientCert = signCertificationRequest(csr, caPrivate, caCert, keyPair, serial, validFrom, validTo);

        X509Certificate[] outChain = {clientCert, caCert};

        KeyStore outStore = KeyStore.getInstance("PKCS12", BC);
        outStore.load(null, null);
        outStore.setKeyEntry(keyAlias, keyPair.getPrivate(), keyPassword, outChain);
        outStore.store(outputStream, keyPassword);
    }

    /**
     * Signs generated certificate with Certification Authority's key
     *
     * @param csr certification request for generated key pair
     * @param caPrivate Certification Authority's private key
     * @param caCert Certification Authority's certificate
     * @param keyPair generated key pair
     * @param serial serial number of generating certificate
     * @param validFrom validFrom of generating certificate
     * @param validTo validTo of generating certificate
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws SignatureException
     * @throws IOException
     * @throws OperatorCreationException
     * @throws CertificateException
     */
    public X509Certificate signCertificationRequest(PKCS10CertificationRequest csr, PrivateKey caPrivate,
                                                    X509Certificate caCert, KeyPair keyPair, BigInteger serial,
                                                    Date validFrom, Date validTo)
            throws InvalidKeyException, NoSuchAlgorithmException,
            NoSuchProviderException, SignatureException, IOException,
            OperatorCreationException, CertificateException {

        AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find("SHA1withRSA");
        AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);

        AsymmetricKeyParameter keyParameter = PrivateKeyFactory.createKey(caPrivate.getEncoded());
        SubjectPublicKeyInfo keyInfo = SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());

        X509v3CertificateBuilder myCertificateGenerator = new X509v3CertificateBuilder(
                JcaX500NameUtil.getIssuer(caCert), serial, validFrom, validTo, csr.getSubject(), keyInfo);

        ContentSigner sigGen = new BcRSAContentSignerBuilder(sigAlgId, digAlgId).build(keyParameter);

        X509CertificateHolder holder = myCertificateGenerator.build(sigGen);
        Certificate certificateStructure = holder.toASN1Structure();

        CertificateFactory cf = CertificateFactory.getInstance("X.509", BC);

        InputStream is = new ByteArrayInputStream(certificateStructure.getEncoded());
        X509Certificate theCert = (X509Certificate) cf.generateCertificate(is);
        is.close();
        return theCert;
    }

    /**
     * This will initialize the key pair generator for certain keysize and generates a new key pair every time it is called.
     *
     * @param keySize this is an algorithm-specific metric, such as modulus length, specified in number of bits.
     * @return generated key pair
     */
    private KeyPair generateKeyPair(int keySize) throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", BC);
        keyPairGenerator.initialize(keySize);
        return keyPairGenerator.generateKeyPair();
    }

    public int getKeySize() {
        return keySize;
    }

    public void setKeySize(int keySize) {
        this.keySize = keySize;
    }

    public void setCaPrivate(PrivateKey caPrivate) {
        this.caPrivate = caPrivate;
    }

    public void setCaCert(X509Certificate caCert) {
        this.caCert = caCert;
    }
}
