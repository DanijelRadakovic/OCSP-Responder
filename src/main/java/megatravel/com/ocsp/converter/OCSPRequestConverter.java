package megatravel.com.ocsp.converter;

import megatravel.com.ocsp.util.exception.GeneralException;
import megatravel.com.ocsp.util.exception.OCSPException;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1StreamParser;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.springframework.http.HttpInputMessage;
import org.springframework.http.HttpOutputMessage;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.converter.AbstractHttpMessageConverter;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.http.converter.HttpMessageNotWritableException;

import java.io.IOException;

public class OCSPRequestConverter extends AbstractHttpMessageConverter<OCSPReq> {

    public OCSPRequestConverter() {
        super(new MediaType("application", "ocsp-request"));
    }

    @Override
    protected boolean supports(Class<?> aClass) {
        return OCSPReq.class.isAssignableFrom(aClass);
    }

    @Override
    protected OCSPReq readInternal(Class<? extends OCSPReq> aClass, HttpInputMessage httpInputMessage)
            throws HttpMessageNotReadableException {

        try {
            ASN1Encodable asn1 = new ASN1StreamParser(httpInputMessage.getBody()).readObject();
            if (asn1 == null) {
                throw new OCSPException(new OCSPRespBuilder().build(OCSPRespBuilder.MALFORMED_REQUEST, null),
                        HttpStatus.BAD_REQUEST);
            } else {
                return new OCSPReq(asn1.toASN1Primitive().getEncoded());
            }
        } catch (IOException e) {
            try {
                throw new OCSPException(new OCSPRespBuilder().build(OCSPRespBuilder.MALFORMED_REQUEST, null),
                        HttpStatus.BAD_REQUEST);
            } catch (org.bouncycastle.cert.ocsp.OCSPException ex) {
                throw new GeneralException("Could not create OCSP response", HttpStatus.INTERNAL_SERVER_ERROR);
            }
        } catch (org.bouncycastle.cert.ocsp.OCSPException e) {
            throw new GeneralException("Could not create OCSP response", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @Override
    protected void writeInternal(OCSPReq ocspReq, HttpOutputMessage httpOutputMessage)
            throws IOException, HttpMessageNotWritableException {
        httpOutputMessage.getBody().write(ocspReq.getEncoded());
    }

}
