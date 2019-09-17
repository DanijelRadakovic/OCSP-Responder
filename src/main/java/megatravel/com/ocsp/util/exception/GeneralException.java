package megatravel.com.ocsp.util.exception;

import org.springframework.http.HttpStatus;

/**
 * General error exception
 */
public class GeneralException extends RuntimeException {

    private HttpStatus httpStatus;

    public GeneralException() {
    }

    public GeneralException(String message, HttpStatus httpStatus) {

        super(message);
        this.httpStatus = httpStatus;
    }

    public HttpStatus getHttpStatus() {
        return httpStatus;
    }

    public void setHttpStatus(HttpStatus httpStatus) {
        this.httpStatus = httpStatus;
    }
}
