package mod.alucard.tn.apksigner;

import android.util.Log;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.android.apksig.ApkSigner.SignerConfig;
import com.android.apksig.KeyConfig;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import kellinwood.security.zipsigner.optional.KeyStoreFileManager;
import mod.jbk.build.BuiltInLibraries;

public class ApkSigner {

    private static final File EXTRACTED_TESTKEY_FILES_DIRECTORY = new File(BuiltInLibraries.EXTRACTED_COMPILE_ASSETS_PATH, "testkey");

    // Ký APK bằng testkey có sẵn với cả ba scheme V1, V2 và V3.
    public void signWithTestKey(@NonNull String inputPath, @NonNull String outputPath, @Nullable LogCallback callback) throws Exception {
        try (LogWriter logger = new LogWriter(callback)) {
            long savedTimeMillis = System.currentTimeMillis();
            logger.write("Signing APK with testkey using direct ApkSigner API...");

            PrivateKey privateKey = readPrivateKey(new File(EXTRACTED_TESTKEY_FILES_DIRECTORY, "testkey.pk8"));
            X509Certificate certificate = readCertificate(new File(EXTRACTED_TESTKEY_FILES_DIRECTORY, "testkey.x509.pem"));

            SignerConfig signerConfig = new SignerConfig.Builder("CERT", new KeyConfig.Jca(privateKey),
                    Collections.singletonList(certificate)).build();

            signApk(new File(inputPath), new File(outputPath), Collections.singletonList(signerConfig));

            logger.write("Signing APK took " + (System.currentTimeMillis() - savedTimeMillis) + " ms");
        } catch (Exception e) {
            logFailure(callback, e);
            throw e;
        }
    }

    // Ký APK bằng keystore của người dùng với cả ba scheme V1, V2 và V3.
    public void signWithKeyStore(@NonNull String inputFilePath, @NonNull String outputFilePath,
                                 @NonNull String keyStorePath, @NonNull String keyStorePassword,
                                 @NonNull String keyStoreKeyAlias, @NonNull String keyPassword,
                                 @Nullable LogCallback callback) throws Exception {
        try (LogWriter logger = new LogWriter(callback)) {
            long savedTimeMillis = System.currentTimeMillis();
            logger.write("Signing APK with Keystore using direct ApkSigner API...");

            /* KeyStoreFileManager supports both JKS and BKS keystores */
            KeyStore keyStore = KeyStoreFileManager.loadKeyStore(keyStorePath, keyStorePassword.toCharArray());
            Key key = keyStore.getKey(keyStoreKeyAlias, keyPassword.toCharArray());
            if (!(key instanceof PrivateKey)) {
                throw new KeyStoreException("No private key found for alias \"" + keyStoreKeyAlias + "\"");
            }

            List<X509Certificate> certificates = readCertificateChain(keyStore, keyStoreKeyAlias);
            if (certificates.isEmpty()) {
                throw new KeyStoreException("No certificate found for alias \"" + keyStoreKeyAlias + "\"");
            }

            SignerConfig signerConfig = new SignerConfig.Builder(keyStoreKeyAlias,
                    new KeyConfig.Jca((PrivateKey) key), certificates).build();

            signApk(new File(inputFilePath), new File(outputFilePath), Collections.singletonList(signerConfig));

            logger.write("Signing APK took " + (System.currentTimeMillis() - savedTimeMillis) + " ms");
        } catch (Exception e) {
            logFailure(callback, e);
            throw e;
        }
    }

    // Ghi chữ ký V1, V2 và V3 vào APK đầu ra.
    private void signApk(File inputApk, File outputApk, List<SignerConfig> signerConfigs) throws Exception {
        new com.android.apksig.ApkSigner.Builder(signerConfigs)
                .setInputApk(inputApk)
                .setOutputApk(outputApk)
                .setV1SigningEnabled(true)
                .setV2SigningEnabled(true)
                .setV3SigningEnabled(true)
                .build()
                .sign();
    }

    // Đọc chuỗi chứng chỉ X.509 của một mục trong keystore.
    private List<X509Certificate> readCertificateChain(KeyStore keyStore, String alias) throws Exception {
        Certificate[] chain = keyStore.getCertificateChain(alias);
        if (chain == null) {
            return Collections.emptyList();
        }

        List<X509Certificate> certificates = new ArrayList<>();
        for (Certificate certificate : chain) {
            if (certificate instanceof X509Certificate) {
                certificates.add((X509Certificate) certificate);
            }
        }
        return certificates;
    }

    // Đọc khóa riêng RSA được mã hóa theo chuẩn PKCS#8.
    private PrivateKey readPrivateKey(File keyFile) throws Exception {
        byte[] keyBytes = Files.readAllBytes(keyFile.toPath());
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        return KeyFactory.getInstance("RSA").generatePrivate(spec);
    }

    // Đọc chứng chỉ X.509 từ tệp PEM.
    private X509Certificate readCertificate(File certFile) throws Exception {
        try (InputStream is = new FileInputStream(certFile)) {
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(is);
        }
    }

    // Ghi chi tiết lỗi ký APK vào callback để hiển thị cho người dùng.
    private static void logFailure(@Nullable LogCallback callback, Exception e) {
        if (callback != null) {
            callback.onNewLineLogged(Log.getStackTraceString(e));
        }
    }

    public interface LogCallback {
        void onNewLineLogged(String line);
    }

    private static class LogWriter extends OutputStream {

        private final LogCallback mCallback;
        private String mCache = "";

        private LogWriter(LogCallback callback) {
            mCallback = callback;
        }

        @Override
        public void write(int b) {
            if (isLoggingDisabled()) return;

            mCache += (char) b;

            if (((char) b) == '\n') {
                mCallback.onNewLineLogged(mCache);
                mCache = "";
            }
        }

        private void write(String s) {
            if (isLoggingDisabled()) return;

            for (byte b : s.getBytes()) {
                write(b);
            }
        }

        private boolean isLoggingDisabled() {
            return mCallback == null;
        }
    }
}
