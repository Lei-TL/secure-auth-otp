package org.secure_auth_otp.security.totp;

import org.apache.commons.codec.binary.Base32;
import org.springframework.stereotype.Component;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.Locale;

@Component
public class HotpGenerator {

    private static final String HMAC_ALGO = "HmacSHA1";

    public record DebugInfo(long counter, String otp, String hmacHex, int offset, int binaryCode) {}

    public DebugInfo generateDebug(String secretBase32, long counter, int digits) {
        byte[] key = decodeBase32(secretBase32);
        return generateForCounter(key, counter, digits);
    }

    public String generate(String secretBase32, long counter, int digits) {
        return generateDebug(secretBase32, counter, digits).otp();
    }

    public DebugInfo verify(String secretBase32, long counter, String otp, int window, int digits) {
        String sanitized = otp == null ? "" : otp.trim();
        if (sanitized.length() != digits) {
            return null;
        }
        byte[] key = decodeBase32(secretBase32);
        for (int i = -window; i <= window; i++) {
            long c = counter + i;
            DebugInfo candidate = generateForCounter(key, c, digits);
            if (candidate.otp().equals(sanitized)) {
                return candidate;
            }
        }
        return null;
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
            throw new IllegalStateException("Cannot generate HOTP", e);
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


