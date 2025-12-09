package org.secure_auth_otp.security.totp;

import org.apache.commons.codec.binary.Base32;
import org.springframework.stereotype.Component;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.time.Instant;
import java.util.Locale;

@Component
public class TotpGenerator {

    private static final String HMAC_ALGO = "HmacSHA1";
    private static final int DEFAULT_TIME_STEP_SECONDS = 30;
    private static final int DEFAULT_DIGITS = 6;

    public record DebugInfo(long counter, String otp, String hmacHex, int offset, int binaryCode) {}

    public String generate(String secretBase32, Instant time) {
        return generate(secretBase32, time, DEFAULT_TIME_STEP_SECONDS, DEFAULT_DIGITS);
    }

    public String generate(String secretBase32, Instant time, int timeStepSeconds, int digits) {
        DebugInfo debug = generateDebug(secretBase32, time, timeStepSeconds, digits);
        return debug.otp();
    }

    public DebugInfo generateDebug(String secretBase32, Instant time, int timeStepSeconds, int digits) {
        byte[] key = decodeBase32(secretBase32);
        long counter = time.getEpochSecond() / timeStepSeconds;
        return generateForCounter(key, counter, digits);
    }

    public boolean verify(String secretBase32, String otp, Instant time, int window) {
        return verify(secretBase32, otp, time, window, DEFAULT_TIME_STEP_SECONDS, DEFAULT_DIGITS);
    }

    public boolean verify(String secretBase32, String otp, Instant time, int window, int timeStepSeconds, int digits) {
        String sanitized = otp == null ? "" : otp.trim();
        if (sanitized.length() != digits) {
            return false;
        }
        byte[] key = decodeBase32(secretBase32);
        long currentCounter = time.getEpochSecond() / timeStepSeconds;
        for (int i = -window; i <= window; i++) {
            long counter = currentCounter + i;
            DebugInfo candidate = generateForCounter(key, counter, digits);
            if (candidate.otp().equals(sanitized)) {
                return true;
            }
        }
        return false;
    }

    private byte[] decodeBase32(String secretBase32) {
        Base32 base32 = new Base32();
        return base32.decode(secretBase32.toUpperCase(Locale.ROOT));
    }

    private DebugInfo generateForCounter(byte[] key, long counter, int digits) {
        byte[] data = ByteBuffer.allocate(8).putLong(counter).array();
        byte[] hmac = hmacSha1(key, data);

        int offset = hmac[hmac.length - 1] & 0xf;
        int binary =
                ((hmac[offset] & 0x7f) << 24) |
                        ((hmac[offset + 1] & 0xff) << 16) |
                        ((hmac[offset + 2] & 0xff) << 8) |
                        (hmac[offset + 3] & 0xff);
        int otp = binary % (int) Math.pow(10, digits);
        String otpStr = String.format("%0" + digits + "d", otp);
        return new DebugInfo(counter, otpStr, toHex(hmac), offset, binary);
    }

    private byte[] hmacSha1(byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance(HMAC_ALGO);
            mac.init(new SecretKeySpec(key, HMAC_ALGO));
            return mac.doFinal(data);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Cannot generate TOTP", e);
        }
    }

    private String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}

