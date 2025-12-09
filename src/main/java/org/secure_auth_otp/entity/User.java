package org.secure_auth_otp.entity;

import jakarta.persistence.*;
import lombok.Data;

import java.time.LocalDateTime;

@Data
@Entity
@Table(name = "users")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String email;

    @Column(name = "password_hash", nullable = false)
    private String passwordHash;

    @Column(nullable = false)
    private boolean active = false;

    @Column(nullable = false)
    private boolean mfaEnabled = true;

    @Column
    private String totpSecret;

    @Column(nullable = false)
    private boolean totpEnabled = false;

    @Column(nullable = false)
    private int totpFailedAttempts = 0;

    private LocalDateTime totpLockoutUntil;

    @Column(nullable = false)
    private int failedLoginAttempts = 0;

    private LocalDateTime lockoutUntil;

    private LocalDateTime createdAt;

    @PrePersist
    public void prePersist() {
        createdAt = LocalDateTime.now();
    }

}
