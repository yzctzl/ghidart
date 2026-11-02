package ghidart;

import java.io.EOFException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * Bounded binary stream reader for Dart AOT snapshot data.
 *
 * Implements the official variable-length integer encodings (VLE) used across
 * the supported Dart snapshot formats:
 * - ReadUnsigned: 7 bits per byte, little-endian, marker 128 (byte > 127 terminates).
 * - ReadTagged32 / ReadTagged64: signed LEB128, marker 192 (terminator subtracts 192).
 * - ReadRefId: big-endian signed byte accumulation (Dart >= 2.18).
 */
public final class DartStream {
  private final byte[] data;
  private int pos;
  private final int start;
  private long maxRef = Long.MAX_VALUE;
  private java.util.function.BooleanSupplier cancelled = () -> false;
  private int reads;
  private final int end;

  public DartStream(byte[] data) {
    this(data, 0, data != null ? data.length : 0);
  }

  public DartStream(byte[] data, int offset) {
    this(data, offset, data != null ? data.length - offset : 0);
  }

  public DartStream(byte[] data, int offset, int length) {
    if (data == null) {
      throw new IllegalArgumentException("data cannot be null");
    }
    if (offset < 0 || length < 0 || offset > data.length - length) {
      throw new IllegalArgumentException("stream region outside input");
    }
    this.data = data;
    this.start = offset;
    this.pos = offset;
    this.end = offset + length;
  }

  public int position() {
    return pos;
  }

  public void setPosition(int position) {
    if (position < start || position > end) {
      throw new IllegalArgumentException(
          "invalid stream position: " + position + " (valid range: " + start + ".." + end + ")");
    }
    this.pos = position;
  }

  public void skip(int bytes) throws IOException {
    if (bytes < 0) {
      throw new IllegalArgumentException("cannot skip negative bytes: " + bytes);
    }
    require(bytes);
    pos += bytes;
  }

  public int remaining() {
    return end - pos;
  }

  public boolean hasRemaining() {
    return pos < end;
  }

  public byte readByte() throws IOException {
    if ((reads++ & 1023) == 0 && cancelled.getAsBoolean()) throw new java.io.InterruptedIOException("snapshot parsing cancelled");
    if (pos >= end) {
      throw new EOFException("unexpected end of stream at position " + pos);
    }
    return data[pos++];
  }

  public int readUint8() throws IOException {
    return readByte() & 0xff;
  }

  public byte[] readBytes(int length) throws IOException {
    if (length < 0) {
      throw new IllegalArgumentException("negative read length: " + length);
    }
    require(length);
    byte[] slice = Arrays.copyOfRange(data, pos, pos + length);
    pos += length;
    return slice;
  }

  public int readUint16() throws IOException {
    if (2 > end - pos) {
      throw new EOFException("unexpected end of stream reading uint16 at position " + pos);
    }
    int b0 = data[pos++] & 0xff;
    int b1 = data[pos++] & 0xff;
    return b0 | (b1 << 8);
  }

  public int readInt16() throws IOException {
    return (short) readUint16();
  }

  public int readInt32() throws IOException {
    if (4 > end - pos) {
      throw new EOFException("unexpected end of stream reading int32 at position " + pos);
    }
    int b0 = data[pos++] & 0xff;
    int b1 = data[pos++] & 0xff;
    int b2 = data[pos++] & 0xff;
    int b3 = data[pos++] & 0xff;
    return b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
  }

  public long readUint32() throws IOException {
    return readInt32() & 0xffffffffL;
  }

  public long readInt64() throws IOException {
    if (8 > end - pos) {
      throw new EOFException("unexpected end of stream reading int64 at position " + pos);
    }
    long b0 = data[pos++] & 0xffL;
    long b1 = data[pos++] & 0xffL;
    long b2 = data[pos++] & 0xffL;
    long b3 = data[pos++] & 0xffL;
    long b4 = data[pos++] & 0xffL;
    long b5 = data[pos++] & 0xffL;
    long b6 = data[pos++] & 0xffL;
    long b7 = data[pos++] & 0xffL;
    return b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
        | (b4 << 32) | (b5 << 40) | (b6 << 48) | (b7 << 56);
  }

  /**
   * Reads an unsigned variable-length integer (kEndByteMarker = 128).
   *
   * Each byte carries 7 bits. If byte > 127, it terminates and contributes
   * {@code (byte - 128) << shift}.
   */
  public long readUnsigned() throws IOException {
    long value = 0;
    for (int shift = 0; shift <= 63; shift += 7) {
      int b = readUint8();
      int payload = b & 127;
      if (shift == 63 && payload > 1) {
        throw new IOException("unsigned VLE overflow at " + pos);
      }
      value |= (long) payload << shift;
      if (b >= 128) return value;
    }
    throw new IOException("unterminated unsigned VLE at " + pos);
  }

  /** Signed Dart VLE, with a final byte biased by 192 rather than 128. */
  public int readTagged32() throws IOException {
    long value = readSigned(32);
    return (int) value;
  }

  public long readTagged64() throws IOException {
    return readSigned(64);
  }

  private long readSigned(int bits) throws IOException {
    long value = 0;
    for (int shift = 0; shift < bits; shift += 7) {
      int b = readUint8();
      if (b >= 128) {
        long last = b - 192;
        int remaining = bits - shift;
        if (remaining < 7 && (last < -(1L << (remaining - 1))
            || last >= (1L << (remaining - 1)))) {
          throw new IOException("signed VLE overflow at " + pos);
        }
        return value | (last << shift);
      }
      value |= (long) b << shift;
    }
    throw new IOException("unterminated signed VLE at " + pos);
  }

  /**
   * Reads a Dart object reference ID using big-endian signed byte accumulation.
   *
   * Used in Dart >= 2.18 for compressed and signed references:
   * {@code result = byte + (result << 7)}, terminating when {@code byte < 0}.
   * Final value is {@code result + 128}.
   */
  public long readRefId() throws IOException {
    long result = 0;
    for (int i = 0; i < 5; i++) {
      byte b = readByte();
      result = (long) b + (result << 7);
      if (b < 0) {
        long ref = result + 128;
        return ref;
      }
    }
    throw new IOException("VLE ref ID overflow at position " + pos);
  }

  /**
   * Reads an object reference ID according to version encoding:
   * - If {@code fillRefUnsigned == true} (Dart <= 2.17): calls {@link #readUnsigned()}.
   * - If {@code fillRefUnsigned == false} (Dart >= 2.18): calls {@link #readRefId()}.
   */
  public long readRef(boolean fillRefUnsigned) throws IOException {
    long ref = fillRefUnsigned ? readUnsigned() : readRefId();
    checkRef(ref);
    return ref;
  }

  /** Reads a null-terminated UTF-8 / ASCII C-string. */
  public String readCString() throws IOException {
    int start = pos;
    while (pos < end) {
      if (data[pos] == 0) {
        String str = new String(data, start, pos - start, StandardCharsets.UTF_8);
        pos++; // skip null terminator
        return str;
      }
      pos++;
    }
    throw new EOFException("unterminated C-string starting at position " + start);
  }

  public void setCancellation(java.util.function.BooleanSupplier cancelled) {
    this.cancelled = cancelled;
  }

  /** Limit Fill references to this snapshot's allocated reference table. */
  public void limitReferences(long maximum) {
    maxRef = maximum;
  }

  private void checkRef(long ref) throws IOException {
    if (ref <= 0 || ref > maxRef) throw new IOException("reference outside snapshot: " + ref);
  }

  private void require(int count) throws IOException {
    if (cancelled.getAsBoolean()) throw new java.io.InterruptedIOException("snapshot parsing cancelled");
    if (count < 0 || count > end - pos) throw new EOFException("stream region exhausted at " + pos);
  }

  public void align(int alignment) throws IOException {
    if (alignment <= 0 || (alignment & (alignment - 1)) != 0) {
      throw new IllegalArgumentException("alignment must be a positive power of two");
    }
    skip((-pos) & (alignment - 1));
  }
}
