package org.secure_auth_otp.service;

public interface OtpService {

    public void sendOtp(String email, String purpose);

    public boolean verifyOtp(String email, String purpose, String inputOtp);

}

