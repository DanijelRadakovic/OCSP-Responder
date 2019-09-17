package megatravel.com.ocsp.service;

import megatravel.com.ocsp.config.OCSPConfig;
import megatravel.com.ocsp.domain.OCSPCertificateStatusDescriptor;
import megatravel.com.ocsp.domain.enums.RevokeReason;
import megatravel.com.ocsp.repository.CertificateRepository;
import megatravel.com.ocsp.util.exception.ValidationException;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.*;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.*;
import java.util.stream.Collectors;

@Service
public class OCSPService {

    private static final Logger LOGGER = LoggerFactory.getLogger(OCSPService.class);

    @Autowired
    private OCSPConfig config;

    @Autowired
    private CertificateRepository repository;

    /**
     * issuer of certificate that signs OCSP response
     */
    private X509CertificateHolder issuingCertificate;
    /**
     * certificate chain of certificate that signs OCSP response
     */
    private X509CertificateHolder[] signingCertificateChain;

    private RespID responderID;
    private DigestCalculatorProvider digestCalculatorProvider;
    private ContentSigner contentSigner;


    @PostConstruct
    private void init() throws IllegalArgumentException {
        try {
            KeyStore keystore = KeyStore.getInstance("PKCS12");
            keystore.load(new FileInputStream(config.getKeystore()), config.getKeystorePassword().toCharArray());
            Certificate[] certs = keystore.getCertificateChain(config.getKeystoreAlias());

            signingCertificateChain = new X509CertificateHolder[certs.length];
            for (int i = 0; i < certs.length; i++) {
                signingCertificateChain[i] = new JcaX509CertificateHolder((X509Certificate) certs[i]);
            }
            issuingCertificate = signingCertificateChain[1];

            digestCalculatorProvider = new JcaDigestCalculatorProviderBuilder()
                    .setProvider(config.getProvider())
                    .build();
            responderID = new RespID(signingCertificateChain[0].getSubjectPublicKeyInfo(),
                    // only SHA-1 support with RespID
                    digestCalculatorProvider.get(new DefaultDigestAlgorithmIdentifierFinder().find("SHA-1")));

            Key key = keystore.getKey(config.getKeystoreAlias(), config.getKeystorePassword().toCharArray());
            if (key instanceof PrivateKey) {
                try {
                    contentSigner = new JcaContentSignerBuilder("SHA256withRSA")
                            .setProvider(config.getProvider())
                            .build((PrivateKey) key);
                } catch (OperatorCreationException e) {
                    LOGGER.info("action=ocspServiceInit status=failure cause=badlyConstructedContentSigner");
                    throw new IllegalArgumentException("Could not build contentSigner", e);
                }
            }
        } catch (KeyStoreException | CertificateException e) {
            LOGGER.info("action=ocspServiceInit status=failure cause=unrecognizedProvider", e);
            throw new IllegalArgumentException(e);
        } catch (NoSuchAlgorithmException e) {
            LOGGER.info("action=ocspServiceInit status=failure cause=unrecognizedAlgorithm", e);
            throw new IllegalArgumentException(e);
        } catch (IOException e) {
            LOGGER.info("action=ocspServiceInit status=failure cause=keystoreNotFound", e);
            throw new IllegalArgumentException(e);
        } catch (UnrecoverableKeyException e) {
            LOGGER.info("action=ocspServiceInit status=failure cause=unrecoverableKey", e);
            throw new IllegalArgumentException(e);
        } catch (OperatorCreationException | OCSPException e) {
            LOGGER.info("action=ocspServiceInit status=failure cause=badlyConstructedResponderID", e);
            throw new IllegalArgumentException("Could not build responder id", e);
        }
    }

    /**
     * Checks statuses of certificates requested in OCSP request.
     * Validation of the OCSP request is done before processing.
     *
     * @param ocspReq The OCSP request
     * @return The OCSP response if possible
     * @throws ValidationException if OCSP request was malformed
     * @throws OCSPException       if returning a proper OCSP response is not possible
     */
    public OCSPResp checkCertificateStatus(OCSPReq ocspReq) throws ValidationException, OCSPException {
        validateRequest(ocspReq);
        return processOCSPRequest(ocspReq);
    }

    /**
     * Validates the OCSP request
     *
     * @param ocspReq The OCSP request
     * @throws ValidationException if the request was malformed
     * @throws OCSPException       if error occurs while validating OCSP request
     */
    private void validateRequest(OCSPReq ocspReq) throws ValidationException, OCSPException {
        if (ocspReq == null) {
            LOGGER.info("action=checkCertificateStatus status=failure cause=requestNotFoundInPayload");
            throw new ValidationException("Could not find a request in the payload");
        }
        // Check signature if present
        if (ocspReq.isSigned() && !validateSignature(ocspReq)) {
            LOGGER.info("action=checkCertificateStatus serialNumbers={} status=failure " +
                    "cause=notValidSignatureInOCSPRequest", extractSerialNumbers(ocspReq));
            throw new ValidationException("Not valid signature in OCSP request");
        }
    }

    /**
     * Checks to see if the signature in the OCSP request is valid.
     *
     * @param ocspReq The OCSP request.
     * @return {@code true} if the signature is valid, {@code false} otherwise.
     */
    private boolean validateSignature(OCSPReq ocspReq) throws OCSPException {
        try {
            return ocspReq.isSignatureValid(new JcaContentVerifierProviderBuilder()
                    .setProvider(config.getProvider())
                    .build(ocspReq.getCerts()[0]));
        } catch (CertificateException | OperatorCreationException e) {
            LOGGER.warn("action=checkCertificateStatus status=inProgress warning=unreadableSignature", e);
            return false;
        }
    }

    /**
     * Processes the OCSP request from the client.
     * <p>
     * According to <a href="https://tools.ietf.org/html/rfc6960">RFC 6960 </a> the responder
     * is tasked with the following checks and if any are not true, an error message is returned:
     * <p>
     * 1. the message is well formed,
     * 2. the responder is configured to provide the requested service,
     * 3. the request contains the information needed by the responder.
     * <p>
     * Number one has been already taken care of (we were able to parse it).
     * <p>
     * This method will check the second and third conditions before returning an OCSP response.
     *
     * @param ocspReq The OCSP request
     * @return The OCSP response
     */
    private OCSPResp processOCSPRequest(OCSPReq ocspReq) throws OCSPException {
        BasicOCSPRespBuilder responseBuilder = new BasicOCSPRespBuilder(responderID);

        // Add appropriate extensions
        Collection<Extension> responseExtensions = new ArrayList<>();
        //nonce
        Extension nonceExtension = ocspReq.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
        if (nonceExtension != null) {
            responseExtensions.add(nonceExtension);
        }
        if (config.isRejectUnknown()) {
            responseExtensions.add(new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_extended_revoke,
                    false, new byte[]{}));
        }

        Extension[] extensions = responseExtensions.toArray(new Extension[0]);
        responseBuilder.setResponseExtensions(new Extensions(extensions));

        Req[] requests = ocspReq.getRequestList();

        // Fetch certificates from database
        List<megatravel.com.ocsp.domain.Certificate> certs = repository
                .findBySerialNumbers(Arrays.stream(requests)
                        .map(req -> req.getCertID().getSerialNumber().toString())
                        .collect(Collectors.toList()));

        // Check that each request is valid and put the appropriate response in the builder
        for (Req request : requests) {
            addResponse(responseBuilder, request, certs
                    .stream()
                    .filter(certificate -> certificate.getSerialNumber()
                            .equals(request.getCertID().getSerialNumber().toString()))
                    .findFirst()
                    .orElse(null));
        }
        return buildSignedResponse(responseBuilder);
    }


    /**
     * Adds response for specific cert OCSP request
     *
     * @param responseBuilder The builder containing the full response
     * @param request         The specific cert request
     */
    private void addResponse(BasicOCSPRespBuilder responseBuilder, Req request,
                             megatravel.com.ocsp.domain.Certificate certificate) throws OCSPException {
        CertificateID certificateID = request.getCertID();

        // Build Extensions
        Extensions extensions = new Extensions(new Extension[]{});
        Extensions requestExtensions = request.getSingleRequestExtensions();
        if (requestExtensions != null) {
            Extension nonceExtension = requestExtensions.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
            if (nonceExtension != null) {
                extensions = new Extensions(nonceExtension);
            }
        }

        // Check issuer
        boolean matchesIssuer = certificateID.matchesIssuer(issuingCertificate, digestCalculatorProvider);

        if (!matchesIssuer) {
            LocalDateTime now = LocalDateTime.now();
            CertificateStatus status;
            if (config.isRejectUnknown()) {
                status = new RevokedStatus(Date.from(now.atZone(ZoneId.systemDefault()).toInstant()),
                        RevokeReason.UNSPECIFIED.getCode());
            } else {
                status = new UnknownStatus();
            }
            responseBuilder.addResponse(certificateID, status,
                    Date.from(now.atZone(ZoneId.systemDefault()).toInstant()),
                    Date.from(now.plusSeconds(config.getRefreshRate()).atZone(ZoneId.systemDefault()).toInstant()),
                    extensions);
        } else {
            OCSPCertificateStatusDescriptor status = getOCSPCertificateStatusDescriptor(certificate);
            responseBuilder.addResponse(certificateID, status.getCertificateStatus(),
                    Date.from(status.getCurrentUpdate().atZone(ZoneId.systemDefault()).toInstant()),
                    Date.from(status.getNextUpdate().atZone(ZoneId.systemDefault()).toInstant()),
                    extensions);
        }
    }

    /**
     * Gets the OCSP Certificate Status with the Certificate Status (good, revoked, unknown),
     * the updated date, and the next update date.
     *
     * @param certificate The certificate entity
     * @return OCSP Certificate Status
     */
    private OCSPCertificateStatusDescriptor getOCSPCertificateStatusDescriptor(
            megatravel.com.ocsp.domain.Certificate certificate) {
        CertificateStatus status;
        if (certificate == null) { // certificate does not exist in database
            if (config.isRejectUnknown()) { // return REVOKED status for unknown certificates
                status = new RevokedStatus(Date.from(LocalDateTime.now()
                        .atZone(ZoneId.systemDefault()).toInstant()), RevokeReason.UNSPECIFIED.getCode());
            } else { // UNKNOWN
                status = new UnknownStatus();
            }
        } else if (certificate.isActive() && certificate.getRevokeReason() == null
                && certificate.getExpirationDate().isAfter(LocalDateTime.now())) { // GOOD
            status = CertificateStatus.GOOD;
        } else if (!certificate.isActive() && certificate.getRevokeReason() != null
                && certificate.getExpirationDate().isAfter(LocalDateTime.now())) { // REVOKED
            status = new RevokedStatus(Date.from(certificate.getExpirationDate()
                    .atZone(ZoneId.systemDefault()).toInstant()),
                    certificate.getRevokeReason().getCode());
        } else if (certificate.getExpirationDate().isBefore(LocalDateTime.now())) { // EXPIRED
            status = new RevokedStatus(Date.from(certificate.getExpirationDate()
                    .atZone(ZoneId.systemDefault()).toInstant()), RevokeReason.SUPERSEDED.getCode());
        } else if (config.isRejectUnknown()) { // return REVOKED status for unknown certificates
            status = new RevokedStatus(Date.from(LocalDateTime.now()
                    .atZone(ZoneId.systemDefault()).toInstant()), RevokeReason.UNSPECIFIED.getCode());
        } else { // UNKNOWN
            status = new UnknownStatus();
        }
        LocalDateTime currentUpdate = LocalDateTime.now();
        return new OCSPCertificateStatusDescriptor(status, currentUpdate,
                currentUpdate.plusSeconds(config.getRefreshRate()));
    }

    /**
     * Builds signed response in the builder
     *
     * @param responseBuilder The builder
     * @return The signed response
     */
    private OCSPResp buildSignedResponse(BasicOCSPRespBuilder responseBuilder) throws OCSPException {
        BasicOCSPResp basicResponse = responseBuilder.build(contentSigner, signingCertificateChain, new Date());
        return new OCSPRespBuilder().build(OCSPRespBuilder.SUCCESSFUL, basicResponse);
    }

    private String extractSerialNumbers(OCSPReq ocspReq) {
        StringBuilder serialNumbers = new StringBuilder();
        Req[] request = ocspReq.getRequestList();
        for (int i = 0; i < request.length; i++) {
            serialNumbers.append(request[i].getCertID().getSerialNumber().toString());
            if (i < request.length - 1) {
                serialNumbers.append(";");
            }
        }
        return serialNumbers.toString();
    }
}
