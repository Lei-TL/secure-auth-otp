package org.secure_auth_otp.service.dto;

public record TotpSetup(String secretBase32, String otpauthUrl) {
}

