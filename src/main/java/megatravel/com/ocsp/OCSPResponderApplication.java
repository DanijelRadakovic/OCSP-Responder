package megatravel.com.ocsp;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class OCSPResponderApplication {

    public static void main(String[] args) {
        SpringApplication.run(OCSPResponderApplication.class, args);
    }
}
