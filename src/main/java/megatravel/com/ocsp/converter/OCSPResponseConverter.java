package megatravel.com.ocsp.converter;

import org.bouncycastle.cert.ocsp.OCSPResp;
import org.springframework.http.HttpInputMessage;
import org.springframework.http.HttpOutputMessage;
import org.springframework.http.MediaType;
import org.springframework.http.converter.AbstractHttpMessageConverter;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.http.converter.HttpMessageNotWritableException;

import java.io.IOException;

public class OCSPResponseConverter extends AbstractHttpMessageConverter<OCSPResp> {

    public OCSPResponseConverter() {
        super(new MediaType("application", "ocsp-response"));
    }

    @Override
    protected boolean supports(Class<?> aClass) {
        return OCSPResp.class.isAssignableFrom(aClass);
    }

    @Override
    protected OCSPResp readInternal(Class<? extends OCSPResp> aClass, HttpInputMessage httpInputMessage)
            throws IOException, HttpMessageNotReadableException {
        return new OCSPResp(httpInputMessage.getBody());
    }

    @Override
    protected void writeInternal(OCSPResp ocspResp, HttpOutputMessage httpOutputMessage)
            throws IOException, HttpMessageNotWritableException {
        httpOutputMessage.getBody().write(ocspResp.getEncoded());
    }
}
