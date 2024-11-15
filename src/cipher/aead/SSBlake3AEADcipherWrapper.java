package cipher.aead;

import cipher.SSCipher;
import cipher.exception.IncompleteDealException;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;

import util.ByteUtils;


public class SSBlake3AEADcipherWrapper implements SSCipher {
    private static short payloadSizeMask = 0x3FFF;

    private static byte[] EMPTY_BYTES = new byte[]{};
    private SSBlake3AEAD cipher;
    private byte[] cumulationSecretBytes = EMPTY_BYTES;

    public SSBlake3AEADcipherWrapper(SSBlake3AEAD cipher) {
        this.cipher = cipher;
    }

    @Override
    public byte[] decodeSSBytes(byte[] secretBytes) throws Exception {
        byte[] originBytes;
        try {
            originBytes = cipher.decodeSSBytes(getAndAddCumulation(secretBytes));
            cumulationSecretBytes = EMPTY_BYTES;
        } catch (IncompleteDealException e) {
            originBytes = e.getDealBytes();
            addCumulation(e.getDealLength(), secretBytes);
        }
        return originBytes;
    }

    @Override
    public byte[] encodeSSBytes(byte[] originBytes) throws Exception {
        if (originBytes.length <= payloadSizeMask) {
            return cipher.encodeSSBytes(originBytes);
        }

        ByteBuf resultByteBuf = Unpooled.buffer();
        int readIndex = 0;
        while (readIndex < originBytes.length) {
        byte[] sliceOriginBytes = new byte[Math.min(originBytes.length - readIndex, payloadSizeMask)];
        System.arraycopy(originBytes, readIndex, sliceOriginBytes, 0, sliceOriginBytes.length);
        resultByteBuf.writeBytes(cipher.encodeSSBytes(sliceOriginBytes));
        readIndex += sliceOriginBytes.length;
        }
        return ByteBufUtil.getBytes(resultByteBuf);
    }

    private byte[] getAndAddCumulation(byte[] secretBytes) {
        return ByteUtils.concatenate(cumulationSecretBytes, secretBytes);
    }

    private void addCumulation(int dealLength, byte[] bytes) {
        cumulationSecretBytes = ByteUtils.concatenate(cumulationSecretBytes, bytes);
        cumulationSecretBytes = ByteUtils.subArray(cumulationSecretBytes, dealLength);
    }
}