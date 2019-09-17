package megatravel.com.ocsp.converter;

import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.springframework.context.annotation.Bean;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.stereotype.Component;

@Component
public class OCSPConverter {

    @Bean
    public HttpMessageConverter<OCSPReq> createOCSPRequestConverter() {
        return new OCSPRequestConverter();
    }

    @Bean
    public HttpMessageConverter<OCSPResp> createOCSPResponseConverter() {
        return new OCSPResponseConverter();
    }
}