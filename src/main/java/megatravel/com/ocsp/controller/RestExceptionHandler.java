package megatravel.com.ocsp.controller;

import megatravel.com.ocsp.util.exception.GeneralException;
import megatravel.com.ocsp.util.exception.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.multipart.MultipartException;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import java.io.IOException;

/**
 * Controller that handles REST exceptions
 */
@Order(Ordered.HIGHEST_PRECEDENCE)
@ControllerAdvice
public class RestExceptionHandler extends ResponseEntityExceptionHandler {

    @ExceptionHandler(OCSPException.class)
    public ResponseEntity<OCSPResp> handleOCSPException(OCSPException e) {
        return new ResponseEntity<>(e.getOcspResp(), e.getHttpStatus());
    }

    @ExceptionHandler(GeneralException.class)
    public ResponseEntity<String> handleGeneralException(GeneralException e) {
        return new ResponseEntity<>(e.getMessage(), e.getHttpStatus());
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<String> handleIllegalArgumentException(IllegalArgumentException e) {
        return new ResponseEntity<>(e.getMessage(), HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(NumberFormatException.class)
    public ResponseEntity<String> handleNumberFormatException(NumberFormatException e) {
        return new ResponseEntity<>("Bad number format " + e.getMessage(), HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(IOException.class)
    public ResponseEntity<String> handleIOException(IOException e) {
        return new ResponseEntity<>("Resource can not be found!" + e.getMessage(),
                HttpStatus.INTERNAL_SERVER_ERROR);
    }

    @ExceptionHandler(MultipartException.class)
    public ResponseEntity<String> handleFileToLargeException(MultipartException e) {
        return new ResponseEntity<>("File is too large", HttpStatus.BAD_REQUEST);
    }

}
