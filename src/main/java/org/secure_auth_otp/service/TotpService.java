package org.secure_auth_otp.service;

import org.secure_auth_otp.service.dto.TotpSetup;

public interface TotpService {

    TotpSetup startSetup(String email);

    void enableTotp(String email, String secretBase32, String otpInput);

    void verifyLogin(String email, String otpInput);

    boolean isTotpEnabled(String email);
}

