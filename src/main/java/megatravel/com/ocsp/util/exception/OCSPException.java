package megatravel.com.ocsp.util.exception;

import org.bouncycastle.cert.ocsp.OCSPResp;
import org.springframework.http.HttpStatus;

public class OCSPException extends RuntimeException {

    private OCSPResp ocspResp;
    private HttpStatus httpStatus;

    public OCSPException() {
    }

    public OCSPException(OCSPResp ocspResp, HttpStatus httpStatus) {
        this.ocspResp = ocspResp;
        this.httpStatus = httpStatus;
    }

    public OCSPResp getOcspResp() {
        return ocspResp;
    }

    public void setOcspResp(OCSPResp ocspResp) {
        this.ocspResp = ocspResp;
    }

    public HttpStatus getHttpStatus() {
        return httpStatus;
    }

    public void setHttpStatus(HttpStatus httpStatus) {
        this.httpStatus = httpStatus;
    }
}
