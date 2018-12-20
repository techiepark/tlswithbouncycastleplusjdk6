/**
 * 
 */
package com.techiepark.util.ssl;
 
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Vector;
 
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.prng.ThreadedSeedGenerator;
import org.bouncycastle.crypto.tls.AlertDescription;
import org.bouncycastle.crypto.tls.AlertLevel;
import org.bouncycastle.crypto.tls.Certificate;
import org.bouncycastle.crypto.tls.CipherSuite;
import org.bouncycastle.crypto.tls.DefaultTlsServer;
import org.bouncycastle.crypto.tls.DefaultTlsSignerCredentials;
import org.bouncycastle.crypto.tls.ProtocolVersion;
import org.bouncycastle.crypto.tls.SignatureAlgorithm;
import org.bouncycastle.crypto.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.crypto.tls.TlsServerProtocol;
import org.bouncycastle.crypto.tls.TlsSignerCredentials;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
 
 
/**
 * This Class creates plain server socket and wraps it with tlsServerProtocol
 * and enables TLS V1.2 connection based on BouncyCastle Provider.
 * 
 * 
 */
public class TLSServerSocketConnectionFactory {
 
    private static final Logger logger = LoggerFactory.getLogger(TLSServerSocketConnectionFactory.class.getName());
    private static Certificate bcCert;
    private static KeyPair keyPair;
    private static TLSServerSocketConnectionFactory myInstance = null;
    private static CertificateDetails certificateDetails = new CertificateDetails();;
 
    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }
 
    /**
     * 
     * @return
     */
    private static SecureRandom createSecureRandom() {
        /*
         * We use our threaded seed generator to generate a good random seed. If
         * the user has a better random seed, he should use the constructor with
         * a SecureRandom.
         */
        ThreadedSeedGenerator tsg = new ThreadedSeedGenerator();
        SecureRandom random = new SecureRandom();
 
        /*
         * Hopefully, 20 bytes in fast mode are good enough.
         */
        random.setSeed(tsg.generateSeed(20, true));
 
        return random;
    }
 
    /**
     * 
     */
    private TLSServerSocketConnectionFactory() {        
        loadKeyPairAndCertificate();
    }
 
    /**
     * 
     * @return
     */
    public static synchronized TLSServerSocketConnectionFactory getInstance() {
        if (myInstance == null) {
            myInstance = new TLSServerSocketConnectionFactory();
        }
        return myInstance;
    }
 
    /**
     * This method wraps the plain server socket with TlsServerProtocol and
     * returns the TlsServerProtocol(secure socket)
     * 
     * @param socket
     * @return
     * @throws IOException
     */
    public TlsServerProtocol getTlsServerProtocol(Socket socket) throws IOException {
        TlsServerProtocol serverProtocol = new TlsServerProtocol(socket.getInputStream(), socket.getOutputStream(), createSecureRandom());
        return serverProtocol;
    }
 
    /**
     * Method returns the implementation of DefaultTlsServer
     * 
     * @return
     */
    public DefaultTlsServer getDefaultTLSServer() {
 
        try {
 
            DefaultTlsServer tlsServer = new DefaultTlsServer() {
 
                protected TlsSignerCredentials getRSASignerCredentials() throws IOException {
                    if (keyPair == null || bcCert == null) {
                        logger.error("Error: Unable to create server socket - server certificate or keyPair not found..");
                        throw new IOException("Error: No SSL server certificates found..");
                    }
                    /*
                     * TODO Note that this code fails to provide default value
                     * for the client supported algorithms if it wasn't sent.
                     */
                    SignatureAndHashAlgorithm signatureAndHashAlgorithm = null;
                    Vector<?> sigAlgs = supportedSignatureAlgorithms;
                    if (sigAlgs != null) {
                        for (int i = 0; i < sigAlgs.size(); ++i) {
                            SignatureAndHashAlgorithm sigAlg = (SignatureAndHashAlgorithm) sigAlgs.elementAt(i);
                            if (sigAlg.getSignature() == SignatureAlgorithm.rsa) {
                                signatureAndHashAlgorithm = sigAlg;
                                break;
                            }
                        }
 
                        if (signatureAndHashAlgorithm == null) {
                            return null;
                        }
                    }
                    AsymmetricKeyParameter kp = PrivateKeyFactory.createKey(keyPair.getPrivate().getEncoded());
                    return new DefaultTlsSignerCredentials(context, bcCert, kp, signatureAndHashAlgorithm);
                }
 
                @Override
                public void notifyClientCertificate(Certificate clientCertificate) throws IOException {
                    logger.debug("TLS Server - notify client certificate.. ");
                }
 
                @Override
                public void notifyAlertRaised(short alertLevel, short alertDescription, String message, Throwable cause) {
                    logger.debug("TLS server raised alert: " + AlertLevel.getText(alertLevel) + ", " + AlertDescription.getText(alertDescription));
                    if (message != null) {
                        logger.debug("> " + message);
                    }
                    if (cause != null) {
                        logger.debug("\t", cause);
                    }
                }
 
                @Override
                public void notifyAlertReceived(short alertLevel, short alertDescription) {
                    logger.debug("TLS server received alert: " + AlertLevel.getText(alertLevel) + ", " + AlertDescription.getText(alertDescription));
                }
 
                @Override
                protected ProtocolVersion getMaximumVersion() {
                    return ProtocolVersion.TLSv12;
                }
 
                @Override
                protected ProtocolVersion getMinimumVersion() {
                    return ProtocolVersion.TLSv10;
                }
 
                @Override
                protected int[] getCipherSuites() {
                    return Arrays.concatenate(super.getCipherSuites(), new int[]{CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
                            CipherSuite.TLS_ECDHE_RSA_WITH_ESTREAM_SALSA20_SHA1, CipherSuite.TLS_ECDHE_RSA_WITH_SALSA20_SHA1,
                            CipherSuite.TLS_RSA_WITH_ESTREAM_SALSA20_SHA1, CipherSuite.TLS_RSA_WITH_SALSA20_SHA1,
                            CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384, CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
                            CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
                            CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, CipherSuite.TLS_DHE_DSS_WITH_AES_256_GCM_SHA384,
                            CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, CipherSuite.TLS_DHE_DSS_WITH_AES_128_GCM_SHA256});
                }
                 
                @Override
                public ProtocolVersion getServerVersion() throws IOException {
                    ProtocolVersion serverVersion = super.getServerVersion();
                    logger.debug("TLS server negotiated " + serverVersion);
                    return serverVersion;
                }               
            };
            return tlsServer;
        } catch (Exception e) {
            logger.error("Exception in getDefaultTLSServer()", e);
            e.printStackTrace();
        }
        return null;
    }
 
    /**
     * loads server certificate and RSA keypair from keystore.
     * 
     * @return
     */
    public void loadKeyPairAndCertificate() {
        org.bouncycastle.asn1.x509.Certificate certificate = null;
        FileInputStream fileInputStream = null;
        try {
            File keyStore = new File("/usr/local/config/serverKeystore");
            if (!keyStore.exists()) {
                throw new Exception("Error: No SSL server certificates found..");
            }
            String password = certificateDetails.getPassword();
            char[] passphrase = password.toCharArray();
            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            fileInputStream = new FileInputStream(keyStore);
            ks.load(fileInputStream, passphrase);
            String alias = certificateDetails.getAlias();
            Key key = ks.getKey(alias, passphrase);
            java.security.cert.Certificate cert = null;
            if (key instanceof PrivateKey) {
                cert = ks.getCertificate(alias);
                PublicKey publicKey = cert.getPublicKey();
                keyPair = new KeyPair(publicKey, (PrivateKey) key);
                certificate = org.bouncycastle.asn1.x509.Certificate.getInstance(cert.getEncoded());
                bcCert = new Certificate(new org.bouncycastle.asn1.x509.Certificate[]{certificate});
            }
 
        } catch (Exception e) {
            logger.error("Error while loading server certificate from KeyStore..", e);
        } finally {
            closeResource(fileInputStream);
        }
    }
 
    /**
     * 
     * @param resource
     */
    private static void closeResource(InputStream resource) {
        if (resource != null) {
            try {
                resource.close();
            } catch (IOException e) {
                logger.error("Error closing resource..", e);
            }
        }
    }
 
    /**
     * 
     * @return
     * @throws KeyStoreException
     * @throws IOException
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     */
    public static KeyStore loadDefaultKeyStore() throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        FileInputStream is = new FileInputStream("/usr/local/config/serverKeystore");
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(is, certificateDetails.getPassword().toCharArray());
        return ks;
    }
 
    /**
     * 
     * @param alias
     * @param ks
     * @return
     * @throws UnrecoverableEntryException
     * @throws NoSuchAlgorithmException
     * @throws KeyStoreException
     */
    public static KeyStore.PrivateKeyEntry loadPrivateKey(String alias, KeyStore ks) throws UnrecoverableEntryException, NoSuchAlgorithmException,
            KeyStoreException {
        String password = certificateDetails.getPassword();
        return (KeyStore.PrivateKeyEntry) ks.getEntry(alias, new KeyStore.PasswordProtection(password.toCharArray()));
    }
 
    /**
     * 
     * @param key
     * @return
     * @throws CertificateEncodingException
     * @throws IOException
     */
    public static org.bouncycastle.crypto.tls.Certificate getCert(KeyStore.PrivateKeyEntry key) throws CertificateEncodingException, IOException {
        org.bouncycastle.asn1.x509.Certificate x509cert = org.bouncycastle.asn1.x509.Certificate.getInstance(((X509Certificate) key.getCertificate())
                .getEncoded());
        return new org.bouncycastle.crypto.tls.Certificate(new org.bouncycastle.asn1.x509.Certificate[]{x509cert});
    }
 
    /**
     * 
     * @param key
     * @return
     * @throws IOException
     */
    public static AsymmetricKeyParameter getKeys(KeyStore.PrivateKeyEntry key) throws IOException {
        return PrivateKeyFactory.createKey(key.getPrivateKey().getEncoded());
    }
}