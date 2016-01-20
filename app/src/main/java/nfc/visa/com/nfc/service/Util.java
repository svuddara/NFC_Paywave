package nfc.visa.com.nfc.service;

import android.util.Log;

import java.util.Locale;
import java.util.StringTokenizer;

/**
 * Created by uvashish on 8/24/15.
 */

public class Util implements Constants {

    // Elements of parseDOL() result
    public final static byte TAG = (byte) 0;
    public final static byte LEN = (byte) 1;
    private static short _resultTAG;
    private static short _resultLEN;

    // Utility method. Compares two byte arrays.
    static boolean arrayCompare(
            byte[] array1,
            int array1Offset,
            byte[] array2,
            int array2Offset) {
        // For Application Version Number comparison.
        if (array1 == null)
            return true;

        // For CHV currency comparison.
        if (array2 == null)
            return false;

        int j = array2Offset;
        for (int i = array1Offset; i < (array1Offset + array1.length); i++) {
            if (array2[j++] != array1[i])
                return false;
        }
        return true;
    }

    // Utility method. Compares two byte arrays.
    static boolean arrayCompare(
            byte[] array1,
            int array1Offset,
            byte[] array2,
            int array2Offset,
            int length) {
        // For Application Version Number comparison.
        if (array1 == null)
            return true;

        // For CHV currency comparison.
        if (array2 == null)
            return false;

        int j = array2Offset;
        for (int i = array1Offset; i < (array1Offset + length); i++) {
            if (array2[j++] != array1[i])
                return false;
        }
        return true;
    }

    // Utility method. Convert integer value to string in hex format.
    public static String byteHexString(int val) {
        StringBuffer sb = new StringBuffer();

        val = val & 0xFFFF;
        if ((val & 0xFF00) == 0xFF00)
            val = val & 0x00FF;

        if ((val > 0x0100) && (val < 0x0010))
            sb.append("0");
        else if ((val > 0x00FF) && (val < 0x1000))
            sb.append("0");

        sb.append(Integer.toHexString(val).toUpperCase(Locale.US));

        return sb.toString();
    }

    // Utility method. Display byte array in user-friendly format.
    public static void printArray(String iLOG_TAG, byte[] data, String dataname, int len) {
        Log.i(iLOG_TAG, dataname + ": ");
        Log.i(iLOG_TAG, getHexString(data, 0, len, " "));
    }

    // Utility method. Converts byte array to long value.
    public static long convertArraytoLong(byte[] array, int offset, int length) {
        long result = 0;
        long multiple = 1;
        for (int i = (offset + length - 1); i >= offset; i--) {
            result += multiple * (int) (array[i] & 0xFF);
            multiple *= 256;
        }

        return result;
    }

    // Utility method. Converts byte array to long value.
    public static long convertArraytoLong(byte[] array) {
        return convertArraytoLong(array, 0, array.length);
    }

    // Utility method. Convert string to byte array.
    public static byte[] convertToBytes(String s) {
        if (s == null)
            return null;

        StringTokenizer st = new StringTokenizer(s);
        Integer i;
        byte[] ba = new byte[st.countTokens()];
        int offset = 0;
        while (st.hasMoreTokens()) {
            i = Integer.parseInt(st.nextToken(), 16);
            ba[offset++] = (byte) (0xFF & i.byteValue());
        }

        return ba;
    }

    // Utility method. Convert string to byte array.
    public static byte[] convertToBytes(String s, String seperator, int radix) {
        if (s == null)
            return null;
        byte[] ret = new byte[s.length() / 2];
        if (seperator.equals("")) {
            for (int i = 0, j = 0; i < s.length(); i += 2, j++) {
                ret[j] = (byte) Integer.parseInt(s.substring(i, i + 2), radix);
            }
        } else {
            ret = convertToBytes(s);
        }

        return ret;
    }

    static String getHexString(byte[] data, int offset, int len, String delimiter) {
        if (data != null) {
            StringBuffer str = new StringBuffer(len);
            for (int i = 0; i < len; i++) {
                if (i != 0 && i % 16 == 0) {
                }
                String digit = Integer.toHexString((data[i + offset] & 0x00ff));
                if (digit.length() == 1)
                    digit = '0' + digit;
                digit = digit.toUpperCase(Locale.US);
                str.append(digit + delimiter);
            }
            return str.toString();
        }
        return "";
    }

    static String getAsciiString(byte[] data, int offset, int len, String delimiter) {
        if (data != null) {
            int index;
            StringBuffer str = new StringBuffer(len);
            for (int i = 0; i < len; i++) {
                if (i != 0 && i % 16 == 0) {
                }
                index = i + offset;
                String digit;
                if (data[index] >= ' ' && data[index] <= '}') {
                    char c = (char) (data[i + offset] & 0x00ff);
                    digit = "" + c;
                } else {
                    digit = Integer.toHexString((data[i + offset] & 0x00ff));
                    if (digit.length() == 1)
                        digit = '0' + digit;
                }
                digit = digit.toUpperCase();
                str.append(digit + delimiter);
            }
            return str.toString();
        }
        return "";
    }

    static String getString(byte[] data, int offset, int len, String delimiter) {
        if (data != null) {
            StringBuffer str = new StringBuffer(len);
            for (int i = 0; i < len; i++) {
                if (i != 0 && i % 16 == 0) {
                }
                String digit = Integer.toString((data[i + offset] & 0x00ff));
                if (digit.length() == 1)
                    digit = '0' + digit;
                digit = digit.toUpperCase();
                str.append(digit + delimiter);
            }
            return str.toString();
        }
        return "";
    }

    public static String getHexString(byte[] data) {
        if (data != null) {
            return getHexString(data, 0, data.length, " ");
        }
        return "";
    }

    static void arrayCopy(byte[] src, short startOff, byte[] dest, short destOff, short len) {
        for (int i = 0; i < len; i++) {
            dest[destOff + i] = src[startOff + i];
        }
    }

    // Utility method. Convert byte array in BCD form to long value.
    static long convertBCDtoLong(byte[] array) {
        long result = 0;
        long multiple = 1;
        for (int i = (array.length - 1); i >= 0; i--) {
            result += multiple * (int) (array[i] & 0x0F);
            multiple *= 10;
            result += multiple * (int) (array[i] >> 4);
            multiple *= 10;
        }

        return result;
    }

    /**
     * Stores tag value in BCD format. (used for Amount and Other Amount) (synchronous)
     * <p/>
     *
     * @param tag   tag to be stored.
     * @param value value to be converted to BCD format to be stored.
     */
/*	static void storeBCD(Short tag, long value) {
        byte[] bcdValue = new byte[6];

		String valueStr = (Long.valueOf(value)).toString();
		int offset = valueStr.length() - 1;
		for (int i = 5; i >= 0; i--) {
			bcdValue[i] = (byte) (valueStr.charAt(offset--) - 48);
			if (offset < 0)
				break;
			bcdValue[i] |= (byte) ((valueStr.charAt(offset--) - 48) << 4);
			if (offset < 0)
				break;
		}

		QVSDCAuthentication.storeTagValue(tag, bcdValue);
	}
	*/
    public static byte[] DecToBCDArray(int num) {
        int digits = 0;

        int temp = num;
        while (temp != 0) {
            digits++;
            temp /= 10;
        }

        int byteLen = digits % 2 == 0 ? digits / 2 : (digits + 1) / 2;
        boolean isOdd = digits % 2 != 0;

        byte bcd[] = new byte[byteLen];

        for (int i = 0; i < digits; i++) {
            byte tmp = (byte) (num % 10);

            if (i == digits - 1 && isOdd)
                bcd[i / 2] = tmp;
            else if (i % 2 == 0)
                bcd[i / 2] = tmp;
            else {
                byte foo = (byte) (tmp << 4);
                bcd[i / 2] |= foo;
            }

            num /= 10;
        }

        for (int i = 0; i < byteLen / 2; i++) {
            byte tmp = bcd[i];
            bcd[i] = bcd[byteLen - i - 1];
            bcd[byteLen - i - 1] = tmp;
        }

        return bcd;
    }

    static byte[] getBCD(String value) {
        byte[] bcdValue = new byte[6];

        String valueStr = value;
        int offset = valueStr.length() - 1;
        for (int i = 5; i >= 0; i--) {
            bcdValue[i] = (byte) (valueStr.charAt(offset--) - 48);
            if (offset < 0)
                break;
            bcdValue[i] |= (byte) ((valueStr.charAt(offset--) - 48) << 4);
            if (offset < 0)
                break;
        }

        return bcdValue;
    }

    // Utility method. Convert string to byte array.
    public static byte[] convertToBytes(String s, String seperator) {
        if (s == null)
            return null;
        byte[] ret = new byte[s.length() / 2];
        if (seperator.equals("")) {
            for (int i = 0, j = 0; i < s.length(); i += 2, j++) {
                ret[j] = (byte) Integer.parseInt(s.substring(i, i + 2));
            }
        } else {
            ret = convertToBytes(s);
        }

        return ret;
    }

    static String getString(byte[] data) {
        if (data != null) {
            return getHexString(data, 0, data.length, " ");
        }
        return "";
    }

    /**
     * Concatenates the two parameter bytes to form a short value.
     *
     * @param b1 the first byte ( high order byte ).
     * @param b2 the second byte ( low order byte ).
     * @return the short value - the concatenated result
     */
    public static final short makeShort(byte b1, byte b2) {
        return (short) (((short) b1 << 8) + ((short) b2 & 0xFF));
    }

    /**
     * Concatenates two bytes in a byte array to form a short value.
     *
     * @param bArray byte array.
     * @param bOff   offset within byte array containing first byte (the high order byte).
     * @return the short value - the concatenated result
     */
    public static final short getShort(byte[] bArray, short bOff) {
        return (short) (((short) (bArray[bOff]) << 8) +
                ((short) (bArray[(short) (bOff + 1)]) & 0xFF));
    }

    /**
     * Deposits the short value as two successive bytes at the specified offset in the byte array.
     *
     * @param bArray byte array
     * @param bOff   offset within byte array to deposit the first byte (the high order byte)
     * @param sValue the short value to set into array.
     * @return <code>bOff+2</code>
     * <p/>
     * <p>Note:<ul>
     * <li><em>If the byte array is persistent, this operation is performed atomically.
     * If the commit capacity is exceeded, no operation is performed and a </em><code>TransactionException</code><em>
     * exception is thrown.</em></li></ul>
     * @throws ArrayIndexOutOfBoundsException if the <CODE>bOff</CODE> parameter is negative or if <CODE>bOff+1</CODE> is greater than the length
     *                                        of <CODE>bArray</CODE>
     * @throws NullPointerException           if the <CODE>bArray</CODE> parameter is <CODE>null</CODE>
     * @throws TransactionException           if the operation would cause the commit capacity to be exceeded
     * @see JCSystem.getUnusedCommitCapacity()
     */
    public static final short setShort(byte bArray[], short bOff, short sValue) {
        bArray[bOff] = (byte) (sValue >> 8);
        bArray[bOff + 1] = (byte) sValue;

        return (short) (bOff + 2);
    }

    /**
     * Convert Byte to Hex.
     *
     * @param bytes
     * @return
     */
    public static String byteArrayToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();


        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }


        return sb.toString();
    }

    /**
     * Convert Hex to Byte.
     *
     * @param hexString
     * @return
     */
    public static byte[] hexToByteArray(String hexString) {
        int len = hexString.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hexString.charAt(i), 16) << 4)
                    | Character.digit(hexString.charAt(i + 1), 16));
        }
        return data;
    }

    /**
     * Returns the unsigned value of the byte buffer[offset] as a short.
     *
     * @param buffer
     * @param offset
     * @return
     */
    public static short getUByte(byte[] buffer, short offset) {
        return (short) (buffer[offset] & 0x00FF);
    }

    /**
     * This method parses a byte array (DOL) into its Tag and Length components.
     * <p/>
     * Returns number of bytes proccessed (span)
     * result[0] will hold the TAG
     * result[1] will hold the LEN
     */
    public static short parseDOL(byte[] arr, short offset, short[] result) {
//        if ((result == null) || (result.length < 2))
//            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);

        short off = offset;
        short offsetOfT;
        short lengthOfT;  // 1 or 2

        // Ref: EMV 2000; Book 3; Annex B: "... due to erased or modified TLV..."
        while ((arr[off] == (byte) 0x00) || (arr[off] == (byte) 0xFF))
            off++;

        offsetOfT = off;
        if ((arr[off] & (byte) 0x1F) == (byte) 0x1F)
            do {
                off++;
            }
            while ((arr[off] & 0x80) == 0x80);

        off++;
        lengthOfT = (short) (off - offsetOfT);

        if (lengthOfT == 1)
            result[TAG] = (short) (arr[offsetOfT] & 0xff);
        else if (lengthOfT == 2)
            result[TAG] = (short) (((short) (arr[offsetOfT] & 0xff) << 8) + (short) (arr[(short) (offsetOfT + 1)] & 0xff));
//        else
//        {
//            // *** What do I do if the tag is longer than 2 bytes long???? ***
//            //System.out.println("Error: tag longer than 2 bytes long");
//            //System.exit(-1); // What do I do if the tag is longer than 2 bytes long????
//        }

        // Parse the Length field
        result[LEN] = 0;
        if ((arr[off] & (byte) 0x80) == (byte) 0x00) {
            result[LEN] = (short) arr[off];
        } else {
            short numBytes = (short) (arr[off] & (byte) 0x7F);
            short j = 0;
            while (numBytes > 0) {
                off++;
                j = arr[off];
                result[LEN] += (j < 0 ? j += 256 : j);

                if (numBytes > 1)
                    result[LEN] *= 256;

                numBytes--;
            }
        }

        off++;

        return (short) (off - offset);
    }

    /**
     * Find Field Separator
     *
     * @param a
     * @param off
     * @return
     */
    public static short findFS(byte[] a, short off) {
        byte byt;

        short endOfSearch = (short) a.length;

        for (short i = off; i < endOfSearch; i++) {
            byt = a[i];

            if ((byt & (byte) 0xF0) == (byte) 0xD0)
                return (short) ((i - off) * 2);
            else if ((byt & (byte) 0x0F) == (byte) 0x0D)
                return (short) (((i - off) * 2) + 1);
        }

        return (short) -1;
    }

    /**
     * @param src
     * @param src_position
     * @param dst
     * @param dst_position
     * @param length
     */
    public static void nibbleCopy(byte[] src, short src_position, byte[] dst, short dst_position, short length) {
        short off, i;
        short start, end;

        // These booleans are used to determine if the src or dst positions are on a byte boundry or not.
        boolean sbb = ((src_position % 2) == 0);
        boolean dbb = ((dst_position % 2) == 0);

        // If both src_postion and dst_position are not on a byte boundry; copy the odd nibble first.
        if (!sbb && !dbb) {
            off = (short) (dst_position / 2);
            dst[off] = (byte) ((dst[off] & 0xF0) + (src[(short) (src_position / 2)] & 0x0F));
            length--;
            dst_position++;
            src_position++;
            sbb = dbb = true;
        }

        // If both src_postion and dst_position are even, and length is even then simple arraycopy().
        // If both src_postion and dst_position are even, and length is odd then arraycopy() and last nibble.
        if (sbb && dbb) {
            Util.arrayCopy(src, (short) (src_position / 2), dst, (short) (dst_position / 2), (short) (length / 2));
            if ((length % 2) != 0) {
                off = (short) ((short) (dst_position + length) / 2);
                dst[off] = (byte) ((dst[off] & 0x0F) + (src[(short) ((short) (src_position + length) / 2)] & 0xF0));
            }
            return;
        }

        // The src_position and dst_position are not both the same type (byte boundry or not).
        if (dbb) {
            off = (short) (src_position / 2);
            start = (short) (dst_position / 2);
            end = (short) (start + (length / 2));
            for (i = start; i < end; i++)
                dst[i] = (byte) ((src[off] << 4) + ((src[++off] >> 4) & 0x0F));
            if ((length % 2) != 0)
                dst[i] = (byte) ((dst[i] & 0x0F) + (src[off] << 4));
        } else {
            off = (short) (dst_position / 2);
            start = (short) (src_position / 2);
            end = (short) (start + (length / 2));
            for (i = start; i < end; i++) {
                dst[off] = (byte) ((dst[off] & 0xF0) + ((src[i] >> 4) & 0x0F));
                off++;
                dst[off] = (byte) ((dst[off] & 0x0F) + (src[i] << 4));
            }
            if ((length % 2) != 0)
                dst[off] = (byte) ((dst[off] & 0xF0) + ((src[i] >> 4) & 0x0F));
        }

        return;
    }

    /**
     * @param DOL
     * @param offset
     * @param length
     * @param searchTags
     * @param resultsOffsets
     * @param offsetAdjustment
     * @return
     */
    public static short setDataOffsetsFromDOL(byte[] DOL, short offset, short length, short[] searchTags, short[] resultsOffsets, short offsetAdjustment) {
        //31OCT2013#37
        //31OCT2013#38
        short off, span;
        short dataOffset;
        short expectedDataLenth = 0;

        expectedDataLenth = getDOLdataLength(DOL, offset, length);

        // This will search for each PDOL tag and set the offset for it
        off = offset;
        dataOffset = offsetAdjustment; // For GPO cmd, this would be 7, the byte following the '83 len'.  For GenAC it would be 5.
        if (expectedDataLenth > (short) 127)
            dataOffset++;

        while (off < (short) (offset + length)) {
            span = _parseDOL(DOL, off);

            for (short i = 0; i < searchTags.length; i++) {
                if (_resultTAG == searchTags[i]) {
                    resultsOffsets[i] = dataOffset;
                    break;
                }
            }
            dataOffset += _resultLEN;
            off += span;
        }
        return expectedDataLenth;
    }

    /**
     * This will calc the sum of all the DOL Lengths
     *
     * @param DOL
     * @param offset
     * @param length
     * @return
     */
    public static short getDOLdataLength(byte[] DOL, short offset, short length) {
        short off, span;
        short expectedDataLenth = 0;

        // This will calc the sum of all the DOL Lengths
        for (off = offset; off < (short) (offset + length); off += span) {
            span = _parseDOL(DOL, off);
            expectedDataLenth += _resultLEN;
        }

        return expectedDataLenth;
    }

    /**
     * A PRIVATE VERSION OF THIS METHOD USED ONLY INTERNALLY (NO RESULT ARRAY NEEDED)
     * This method parses a byte array (DOL) into its Tag and Length components.
     * <p/>
     * Returns number of bytes proccessed (span)
     * result[0] will hold the TAG
     * result[1] will hold the LEN
     *
     * @param arr
     * @param offset
     * @return
     */
    private static short _parseDOL(byte[] arr, short offset) {

        //31OCT2013#37
        short off = offset;
        short offsetOfT;
        short lengthOfT;  // 1 or 2

        // Ref: EMV 2000; Book 3; Annex B: "... due to erased or modified TLV..."
        while ((arr[off] == (byte) 0x00) || (arr[off] == (byte) 0xFF))
            off++;

        offsetOfT = off;
        if ((arr[off] & (byte) 0x1F) == (byte) 0x1F)
            do {
                off++;
            }
            while ((arr[off] & 0x80) == 0x80);

        off++;
        lengthOfT = (short) (off - offsetOfT);

        if (lengthOfT == 1)
            _resultTAG = (short) (arr[offsetOfT] & 0xff);
        else if (lengthOfT == 2)
            _resultTAG = (short) (((short) (arr[offsetOfT] & 0xff) << 8) + (short) (arr[(short) (offsetOfT + 1)] & 0xff));


        // Parse the Length field
        _resultLEN = 0;
        _resultLEN = (short) (arr[off] & 0xFF);

        off++;

        return (short) (off - offset);
    }

    public static byte[] XOR(byte[] buffer1, byte[] buffer2) {

        byte[] result = new byte[buffer1.length];

        short n = (short) 0;
        while (n < buffer1.length) {
            result[n] = (byte) (buffer1[n] ^ buffer2[n]);
            n++;
        }

        return result;
    }

    public static short calcKeyLength(byte[] buf, short offset, short length) {
        for (short i = (short) (offset + length - 1); i > offset; i--)
            if (buf[i] == (byte) 0x80)
                return (short) (i - offset);

        return (short) 0;
    }

    /**
     * Adds two 12 byte expanded BCD numbers and stores the result in res.
     *
     * @param a
     * @param b
     * @param res
     * @return
     */
    public static boolean addBCD(byte[] a, byte[] b, byte[] res) {
        byte sum = 0;
        short len = 11;
        while (len >= 0) {
            sum = (byte) (a[len] + b[len] + ((sum > 9) ? 1 : 0));
            res[len--] = (byte) (sum - ((sum > 9) ? (byte) 10 : 0));
        }
        return (sum > 9) ? OVERFLOW : SUCCESS;  // Signal overflow
    }

    // Utility function. Copies data to byte array.
    byte[] copyByteArray(byte[] buffer, int offset, int length) {
        byte[] tempBuffer = new byte[length];

        System.arraycopy(buffer, offset, tempBuffer, 0, length);
        return tempBuffer;
    }
}
