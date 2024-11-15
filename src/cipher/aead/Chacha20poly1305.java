package cipher.aead;

import cipher.SSCipher;
import cipher.exception.IncompleteDealException;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;

import org.bouncycastle.crypto.modes.ChaCha20Poly1305;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import util.HeapByteBufUtil;
import util.ShadowsocksUtils;
import javax.crypto.Mac;
import java.security.SecureRandom;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.crypto.digests.SHA256Digest;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;

public class Chacha20poly1305 implements SSCipher {

    private byte[] decodeSubKey = getRandomBytes(getSaltSize());
    private byte[] decodeNonceBytes = getRandomBytes(getNonceSize());
    private byte[] encodeNonceBytes = getRandomBytes(getNonceSize());
    private byte[] encodeSubKey;
    private final String cipherMethod;
    private final String password;

private final ChaCha20Poly1305 decodeChaCha20Poly1305Cipher = new ChaCha20Poly1305();
private final ChaCha20Poly1305 encodeChaCha20Poly1305Cipher = new ChaCha20Poly1305();

    // Initialize ChaCha20-Poly1305 ciphers

    public Chacha20poly1305(String cipherMethod, String password) {
        this.cipherMethod = cipherMethod;
        this.password = password;
    }

    @Override
    public byte[] decodeSSBytes(byte[] secretBytes) throws Exception {
        int readIndex = 0;
        if (decodeSubKey == null) {
            if (getSaltSize() > secretBytes.length) {
                throw new IncompleteDealException(null, 0);
            }
            byte[] salt = new byte[getSaltSize()];
            System.arraycopy(secretBytes, 0, salt, 0, salt.length);
            decodeSubKey = getSubKey(ShadowsocksUtils.getShadowsocksKey(password, getKeySize()), salt);
            readIndex += salt.length;
        }

        ByteBuf originBytesSummary = Unpooled.buffer();
        while (readIndex < secretBytes.length) {
            // Decode payload length
            if (readIndex + 2 + getTagSize() > secretBytes.length) {
                throw new IncompleteDealException(ByteBufUtil.getBytes(originBytesSummary), readIndex);
            }
            byte[] secretLength = new byte[2 + getTagSize()];
            System.arraycopy(secretBytes, readIndex, secretLength, 0, secretLength.length);
            int originLength = HeapByteBufUtil.getShort(aeDecodeBytes(secretLength), 0);

            if (readIndex + secretLength.length + originLength + getTagSize() > secretBytes.length) {
                throw new IncompleteDealException(ByteBufUtil.getBytes(originBytesSummary), readIndex);
            }
            incrementNonce(decodeNonceBytes);
            readIndex += secretLength.length;

            // Decode payload
            byte[] secretPayload = new byte[originLength + getTagSize()];
            System.arraycopy(secretBytes, readIndex, secretPayload, 0, secretPayload.length);

            byte[] originPayload = aeDecodeBytes(secretPayload);
            incrementNonce(decodeNonceBytes);
            readIndex += secretPayload.length;
            originBytesSummary.writeBytes(originPayload);
        }
        return ByteBufUtil.getBytes(originBytesSummary);
    }

    @Override
    public byte[] encodeSSBytes(byte[] originBytes) throws Exception {
        ByteBuf secretBytesSummary = Unpooled.buffer();
        if (encodeSubKey == null) {
            byte[] salt = getRandomBytes(getSaltSize());
            encodeSubKey = getSubKey(ShadowsocksUtils.getShadowsocksKey(password, getKeySize()), salt);
            secretBytesSummary.writeBytes(salt);
        }

        // Encode payload length
        byte[] originLengthBytes = new byte[2];
        HeapByteBufUtil.setShort(originLengthBytes, 0, originBytes.length);

        byte[] secretLengthBytes = aeEncodeBytes(originLengthBytes);
        incrementNonce(encodeNonceBytes);
        secretBytesSummary.writeBytes(secretLengthBytes);

        // Encode payload
        byte[] secretPayloadBytes = aeEncodeBytes(originBytes);
        incrementNonce(encodeNonceBytes);
        secretBytesSummary.writeBytes(secretPayloadBytes);
        return ByteBufUtil.getBytes(secretBytesSummary);
    }

    private byte[] aeDecodeBytes(byte[] secretBytes) throws Exception {
        KeyParameter key = new KeyParameter(decodeSubKey);
        AEADParameters params = new AEADParameters(key, getTagSize() * 8, decodeNonceBytes, null);
        decodeChaCha20Poly1305Cipher.init(false, params);

        byte[] out = new byte[secretBytes.length - getTagSize()];
        int processLength = decodeChaCha20Poly1305Cipher.processBytes(secretBytes, 0, secretBytes.length, out, 0);
        decodeChaCha20Poly1305Cipher.doFinal(out, processLength);
        return out;
    }

    private byte[] aeEncodeBytes(byte[] originBytes) throws Exception {
        KeyParameter key = new KeyParameter(encodeSubKey);
        AEADParameters params = new AEADParameters(key, getTagSize() * 8, encodeNonceBytes, null);
        encodeChaCha20Poly1305Cipher.init(true, params);

        byte[] out = new byte[originBytes.length + getTagSize()];
        int processLength = encodeChaCha20Poly1305Cipher.processBytes(originBytes, 0, originBytes.length, out, 0);
        encodeChaCha20Poly1305Cipher.doFinal(out, processLength);
        return out;
    }

    private byte[] getRandomBytes(int size) {
        byte[] bytes = new byte[size];
        new SecureRandom().nextBytes(bytes);
        return bytes;
    }

    private void incrementNonce(byte[] nonce) {
        for (int i = 0; i < nonce.length; i++) {
            nonce[i]++;
            if (nonce[i] != 0) {
                break;
            }
        }
    }

    private static byte[] getSubKey(byte[] key, byte[] salt) throws NoSuchAlgorithmException, InvalidKeyException {
        byte[] prk = hkdfExtract(salt, key);
        return hkdfExpand(prk, "ss-subkey".getBytes(), 32);
    }

    private static byte[] hkdfExtract(byte[] salt, byte[] key) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        return mac.doFinal(salt);
    }

    private static byte[] hkdfExpand(byte[] prk, byte[] info, int length) {
        HKDFBytesGenerator hkdf = new HKDFBytesGenerator(new SHA256Digest());
        HKDFParameters params = new HKDFParameters(prk, null, info);
        hkdf.init(params);
        byte[] result = new byte[length];
        hkdf.generateBytes(result, 0, length);
        return result;
    }

    private int getSaltSize() {
        return 32; // Fixed salt size for ChaCha20-IETF-Poly1305
    }

    private int getTagSize() {
        return 16; // Fixed tag size for ChaCha20-IETF-Poly1305
    }

    private int getNonceSize() {
        return 12; // Fixed nonce size for ChaCha20-IETF-Poly1305
    }

    private int getKeySize() {
        // ... (adjust key size for ChaCha20-IETF-Poly1305)
        return 32; // Fixed key size for ChaCha20-IETF-Poly1305
    }

}