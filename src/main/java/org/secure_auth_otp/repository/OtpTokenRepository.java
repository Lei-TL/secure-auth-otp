package org.secure_auth_otp.repository;

import org.secure_auth_otp.entity.OtpToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDateTime;
import java.util.List;

public interface OtpTokenRepository extends JpaRepository<OtpToken, Long> {

    @Query("""
        SELECT o FROM OtpToken o
        WHERE o.email = :email
          AND o.purpose = :purpose
        ORDER BY o.createdAt DESC
    """)
    List<OtpToken> findLatestByEmailAndPurpose(
            @Param("email") String email,
            @Param("purpose") String purpose
    );

    @Query("""
        SELECT COUNT(o) FROM OtpToken o
        WHERE o.email = :email
          AND o.purpose = :purpose
          AND o.createdAt >= :fromTime
    """)
    long countRecentOtp(
            @Param("email") String email,
            @Param("purpose") String purpose,
            @Param("fromTime") LocalDateTime fromTime
    );

    @Modifying
    @Query("""
        UPDATE OtpToken o
        SET o.used = true
        WHERE o.email = :email
          AND o.purpose = :purpose
          AND o.used = false
    """)
    int invalidateActiveTokens(
            @Param("email") String email,
            @Param("purpose") String purpose
    );
}

