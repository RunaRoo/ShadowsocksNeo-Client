package cipher.aead;

import cipher.SSCipher;
import cipher.exception.IncompleteDealException;

import org.bouncycastle.crypto.digests.Blake3Digest;

import util.HeapByteBufUtil;
import util.ShadowsocksUtils;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import util.ByteUtils;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;


/**
 * Shadowsocks 2022 blake3-aes-128/256-gcm encryption
 * @author NanoBee (modified for Shadowsocks 2022)
 * @since 2024/09/21
 */
public class SSBlake3AEAD implements SSCipher {

    private String cipherMethod;
    private String password;

    private byte[] decodeSubKey;
    private byte[] decodeNonceBytes;
    private Cipher decodeGcmCipher;

    private byte[] encodeSubKey;
    private byte[] encodeNonceBytes;
    private Cipher encodeGcmCipher;

    public SSBlake3AEAD(String cipherMethod, String password) {
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

            byte[] key = ShadowsocksUtils.getShadowsocksKey(password, getKeySize());
            byte[] context = "ss-context".getBytes();
            byte[] combined = ByteUtils.concatenate(key, salt);
            decodeSubKey = hkdfExtract(combined, blake3Hash(context));
            readIndex += salt.length;
        }

        ByteBuf originBytesSummary = Unpooled.buffer();
        while (readIndex < secretBytes.length) {
            //decode payload length
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

            //decode payload
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
            byte[] key = ShadowsocksUtils.getShadowsocksKey(password, getKeySize());
            byte[] context = "ss-context".getBytes();
            byte[] combined = ByteUtils.concatenate(key, salt);
            encodeSubKey = hkdfExtract(combined, blake3Hash(context));
            secretBytesSummary.writeBytes(salt);
        }

        //encode payload
        byte[] originLengthBytes = new byte[2];
        HeapByteBufUtil.setShort(originLengthBytes, 0, originBytes.length);

        byte[] secretLengthBytes = aeEncodeBytes(originLengthBytes);
        incrementNonce(encodeNonceBytes);
        secretBytesSummary.writeBytes(secretLengthBytes);

        //encode payload
        byte[] secretPayloadBytes = aeEncodeBytes(originBytes);
        incrementNonce(encodeNonceBytes);
        secretBytesSummary.writeBytes(secretPayloadBytes);

        return ByteBufUtil.getBytes(secretBytesSummary);

    }

    private byte[] aeDecodeBytes(byte[] secretBytes) throws BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, ShortBufferException, InvalidAlgorithmParameterException, IllegalBlockSizeException {
        if (decodeGcmCipher == null) {
            decodeGcmCipher = Cipher.getInstance("AES/GCM/NoPadding");
        }

        byte[] nonce = getDecodeNonceBytes();
        GCMParameterSpec spec = new GCMParameterSpec(getTagSize() * 8, nonce);
        SecretKeySpec keySpec = new SecretKeySpec(decodeSubKey, "AES");

        decodeGcmCipher.init(Cipher.DECRYPT_MODE, keySpec, spec);

        byte[] out = new byte[secretBytes.length - getTagSize()];
        int processLength = decodeGcmCipher.update(secretBytes, 0, secretBytes.length, out, 0);
        decodeGcmCipher.doFinal(out, processLength);
        return out;
    }

    /**
     * encode origin bytes
     * @param originBytes originBytes
     * @return [secretBytes][tag]
     * @throws BadPaddingException ex
     */
    private byte[] aeEncodeBytes(byte[] originBytes) throws Exception {
        if (encodeGcmCipher == null) {
            encodeGcmCipher = Cipher.getInstance("AES/GCM/NoPadding");
        }

        byte[] nonce = getEncodeNonceBytes();
        GCMParameterSpec spec = new GCMParameterSpec(getTagSize() * 8, nonce);
        SecretKeySpec keySpec = new SecretKeySpec(encodeSubKey, "AES");

        encodeGcmCipher.init(Cipher.ENCRYPT_MODE, keySpec, spec);

        byte[] out = new byte[originBytes.length + getTagSize()];
        int processLength = encodeGcmCipher.update(originBytes, 0, originBytes.length, out, 0);
        encodeGcmCipher.doFinal(out, processLength);
        return out;
    }

    private byte[] blake3Hash(byte[] data) throws Exception {
        Blake3Digest hasher = new Blake3Digest(32); // Use the desired output size (e.g., 32 bytes)
        hasher.update(data, 0, data.length);
        byte[] hash = new byte[hasher.getDigestSize()];
        hasher.doFinal(hash, 0);
        return hash;
    }

    private byte[] getSubKey(byte[] key, byte[] salt) throws NoSuchAlgorithmException, InvalidKeyException {
        byte[] prk = hkdfExtract(salt, key);
        return hkdfExpand(prk, "ss-subkey".getBytes(), 32);
    }

    private byte[] hkdfExtract(byte[] salt, byte[] ikm) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(salt, "HmacSHA256"));
        return mac.doFinal(ikm);
    }

    private byte[] hkdfExpand(byte[] prk, byte[] info, int length) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchAlgorithmException, InvalidKeyException {
        Mac mac = Mac.getInstance("HmacSHA256");

        mac.init(new SecretKeySpec(prk, "HmacSHA256"));
        byte[] result = new byte[length];
        byte[] t = new byte[0];
        int offset = 0;
        for (int i = 1; offset < length; i++) {
            mac.update(t);
            mac.update(info);
            mac.update((byte) i);
            t = mac.doFinal();
            int copyLength = Math.min(t.length, length - offset);
            System.arraycopy(t, 0, result, offset, copyLength);
            offset += copyLength;
        }
        return result;
    }

    private byte[] getEncodeNonceBytes() {
        if (encodeNonceBytes == null) {
            encodeNonceBytes = new byte[getNonceSize()];
        }
        return ByteUtils.clone(encodeNonceBytes);
    }

    private byte[] getDecodeNonceBytes() {
        if (decodeNonceBytes == null) {
            decodeNonceBytes = new byte[getNonceSize()];
        }
        return ByteUtils.clone(decodeNonceBytes);
    }

    // increment little-endian encoded unsigned integer b. Wrap around on overflow.
    private void incrementNonce(byte[] nonce) {
        for (int i = 0; i < nonce.length; i++) {
            nonce[i]++;
            if (nonce[i] != 0) {
                break;
            }
        }
    }

    private int getKeySize() {
        switch (cipherMethod) {
            case "2022-blake3-aes-128-gcm":
                return 16;
            case "2022-blake3-aes-192-gcm":
                return 24;
            case "2022-blake3-aes-256-gcm":
                return 32;
            default:
                throw new IllegalArgumentException("not support method: " + cipherMethod);
        }
    }

    private int getSaltSize() {
        switch (cipherMethod) {
            case "2022-blake3-aes-128-gcm":
                return 16;
            case "2022-blake3-aes-192-gcm":
                return 24;
            case "2022-blake3-aes-256-gcm":
                return 32;
            default:
                throw new IllegalArgumentException("not support method: " + cipherMethod);
        }
    }

    private int getTagSize() {
        return 16;
    }

    private int getNonceSize() {
        return 12;
    }

    /**
     * Генерация случайных чисел in byte
     * @param size Количество цифр
     * @return random of bytes
     */
    private byte[] getRandomBytes(int size) {
        byte[] bytes = new byte[size];
        new SecureRandom().nextBytes(bytes);
        return bytes;

    }
}
