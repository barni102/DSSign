import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.Pkcs12SignatureToken;
import eu.europa.esig.dss.validation.CommonCertificateVerifier;
import java.io.IOException;
import java.security.*;


public class main {


    public static void main(String args[]) throws IOException {

        PAdESSignatureParameters parameters = new PAdESSignatureParameters();
        parameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
        parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);

        try (Pkcs12SignatureToken token = new Pkcs12SignatureToken(args[0], new KeyStore.PasswordProtection(args[1].toCharArray()))) {
            DSSPrivateKeyEntry privateKey = token.getKeys().get(0);
            parameters.setSigningCertificate(privateKey.getCertificate());
            parameters.setCertificateChain(privateKey.getCertificateChain());

            CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();
            PAdESService service = new PAdESService(commonCertificateVerifier);
            DSSDocument toSignDocument = new FileDocument(args[2]);
            ToBeSigned dataToSign = service.getDataToSign(toSignDocument, parameters);

            DigestAlgorithm digestAlgorithm = parameters.getDigestAlgorithm();
            SignatureValue signatureValue = token.sign(dataToSign, digestAlgorithm, privateKey);
            DSSDocument signedDocument = service.signDocument(toSignDocument, parameters, signatureValue);
            signedDocument.save(args[3]);

        }
    }
}


 
