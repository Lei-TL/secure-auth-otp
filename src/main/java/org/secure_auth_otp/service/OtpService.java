package org.secure_auth_otp.service;

public interface OtpService {

    int getOtpTtlMinutes();

    int getMaxOtpAttempts();

    void sendOtp(String email, String purpose);

    void resendOtp(String email, String purpose);

    boolean verifyOtp(String email, String purpose, String inputOtp);

}

