package megatravel.com.ocsp.controller;

import megatravel.com.ocsp.service.OCSPService;
import megatravel.com.ocsp.util.exception.GeneralException;
import megatravel.com.ocsp.util.exception.OCSPException;
import megatravel.com.ocsp.util.exception.ValidationException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.Req;
import org.bouncycastle.util.encoders.DecoderException;
import org.bouncycastle.util.encoders.UrlBase64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;

@RestController
@RequestMapping(value = "/api/ocsp", produces = "application/ocsp-response",
        consumes = "application/ocsp-request")
public class OCSPController {

    private static final Logger LOGGER = LoggerFactory.getLogger(OCSPController.class);

    @Autowired
    private OCSPService service;

    /**
     * POST /api/ocsp
     * <p>
     * OCSP request over HTTP via POST
     *
     * @param ocspReq The OCSP request
     * @return The OCSP response
     */
    @PostMapping
    public OCSPResp checkCertificateStatus(@RequestBody OCSPReq ocspReq) {
        LOGGER.info("action=checkCertificateStatus serialNumbers={} status=inProcess", extractSerialNumbers(ocspReq));
        try {
            OCSPResp ocspResp = service.checkCertificateStatus(ocspReq);
            LOGGER.info("action=checkCertificateStatus serialNumbers={} status=success", extractSerialNumbers(ocspReq));
            return ocspResp;
        } catch (org.bouncycastle.cert.ocsp.OCSPException e) {
            LOGGER.error("action=checkCertificateStatus serialNumbers={} status=failure " +
                    "cause=errorOccurredWhileProcessingOCSPRequest", extractSerialNumbers(ocspReq), e);
            try {
                throw new OCSPException(new OCSPRespBuilder().build(OCSPRespBuilder.INTERNAL_ERROR, null),
                        HttpStatus.INTERNAL_SERVER_ERROR);
            } catch (org.bouncycastle.cert.ocsp.OCSPException ex) {
                LOGGER.error("action=checkCertificateStatus status=failure cause=badlyConstructedOCSPResponse");
                throw new GeneralException("Could not create OCSP response", HttpStatus.INTERNAL_SERVER_ERROR);
            }
        } catch (ValidationException e) {
            try {
                throw new OCSPException(new OCSPRespBuilder().build(OCSPRespBuilder.MALFORMED_REQUEST, null),
                        HttpStatus.BAD_REQUEST);
            } catch (org.bouncycastle.cert.ocsp.OCSPException ex) {
                LOGGER.error("action=checkCertificateStatus status=failure cause=badlyConstructedOCSPResponse");
                throw new GeneralException("Could not create OCSP response", HttpStatus.INTERNAL_SERVER_ERROR);
            }
        }
    }


    /**
     * GET /api/ocsp/{encodedOCSPRequest}
     * <p>
     * OCSP request over HTTP via GET
     * This method tries to parse the parameter, returns BAD REQUEST if could not or
     * INTERNAL SERVER ERROR if could not construct valid OCSP response
     *
     * @param encodedOCSPRequest The url-safe, base64 encoded, der encoded, OCSP request
     * @return The OCSP response
     * @throws GeneralException if the OCSP response was badly constructed
     * @throws OCSPException    If the OCSP request was malformed
     */
    @GetMapping("/{encodedOCSPRequest}")
    public OCSPResp checkCertificateStatus(@PathVariable("encodedOCSPRequest") String encodedOCSPRequest)
            throws GeneralException, OCSPException {
        try {
            OCSPReq ocspReq = new OCSPReq(UrlBase64.decode(encodedOCSPRequest));
            LOGGER.info("action=checkCertificateStatus serialNumbers={} status=inProcess",
                    extractSerialNumbers(ocspReq));
            try {
                OCSPResp ocspResp = service.checkCertificateStatus(ocspReq);
                LOGGER.info("action=checkCertificateStatus serialNumbers={} status=success", extractSerialNumbers(ocspReq));
                return ocspResp;
            } catch (org.bouncycastle.cert.ocsp.OCSPException e) {
                LOGGER.error("action=checkCertificateStatus serialNumbers={} status=failure " +
                        "cause=errorOccurredWhileProcessingOCSPRequest", extractSerialNumbers(ocspReq), e);
                try {
                    throw new OCSPException(new OCSPRespBuilder().build(OCSPRespBuilder.INTERNAL_ERROR, null),
                            HttpStatus.INTERNAL_SERVER_ERROR);
                } catch (org.bouncycastle.cert.ocsp.OCSPException ex) {
                    LOGGER.error("action=checkCertificateStatus status=failure cause=badlyConstructedOCSPResponse");
                    throw new GeneralException("Could not create OCSP response", HttpStatus.INTERNAL_SERVER_ERROR);
                }
            }
        } catch (IOException e) {
            try {
                LOGGER.info("action=checkCertificateStatus status=failure cause=badlyConstructedOCSPRequest");
                throw new OCSPException(new OCSPRespBuilder().build(OCSPRespBuilder.MALFORMED_REQUEST, null),
                        HttpStatus.BAD_REQUEST);
            } catch (org.bouncycastle.cert.ocsp.OCSPException ex) {
                LOGGER.error("action=checkCertificateStatus status=failure cause=badlyConstructedOCSPResponse");
                throw new GeneralException("Could not create OCSP response", HttpStatus.INTERNAL_SERVER_ERROR);
            }
        } catch (DecoderException e) {
            try {
                LOGGER.info("action=checkCertificateStatus status=failure cause=badlyEncodedOCSPRequest");
                throw new OCSPException(new OCSPRespBuilder().build(OCSPRespBuilder.MALFORMED_REQUEST, null),
                        HttpStatus.BAD_REQUEST);
            } catch (org.bouncycastle.cert.ocsp.OCSPException ex) {
                LOGGER.error("action=checkCertificateStatus status=failure cause=badlyConstructedOCSPResponse");
                throw new GeneralException("Could not create OCSP response", HttpStatus.INTERNAL_SERVER_ERROR);
            }
        } catch (ValidationException e) {
            try {
                throw new OCSPException(new OCSPRespBuilder().build(OCSPRespBuilder.MALFORMED_REQUEST, null),
                        HttpStatus.BAD_REQUEST);
            } catch (org.bouncycastle.cert.ocsp.OCSPException ex) {
                LOGGER.error("action=checkCertificateStatus status=failure cause=badlyConstructedOCSPResponse");
                throw new GeneralException("Could not create OCSP response", HttpStatus.INTERNAL_SERVER_ERROR);
            }
        }
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

