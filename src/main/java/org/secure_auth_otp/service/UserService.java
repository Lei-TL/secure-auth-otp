package org.secure_auth_otp.service;

public interface UserService {

    public void register(String email, String rawPassword);

    public void verifySignupOtp(String email, String otp);

    public void sendChangePasswordOtp(String email);

    public void changePasswordWithOtp(String email, String otp, String newPassword);

}

