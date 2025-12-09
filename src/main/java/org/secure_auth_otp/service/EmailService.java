package org.secure_auth_otp.service;

public interface EmailService {

    public void sendOtpEmail(String to, String otp, String purpose);

}

