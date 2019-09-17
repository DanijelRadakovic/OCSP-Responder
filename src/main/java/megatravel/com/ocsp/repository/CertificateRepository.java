package megatravel.com.ocsp.repository;

import megatravel.com.ocsp.domain.Certificate;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Collection;
import java.util.List;

public interface CertificateRepository extends JpaRepository<Certificate, Long> {

    @Query(value = "SELECT * FROM certificate WHERE serial_number IN (:serialNumbers)", nativeQuery = true)
    List<Certificate> findBySerialNumbers(@Param("serialNumbers") Collection<String> serialNumbers);
}
