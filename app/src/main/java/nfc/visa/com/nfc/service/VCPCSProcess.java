package nfc.visa.com.nfc.service;


import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.util.Arrays;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import static nfc.visa.com.nfc.service.TLV.Tag_ACCOUNT_PARAMETERS_INDEX;
import static nfc.visa.com.nfc.service.TLV.Tag_ACCOUNT_PARAMETERS_LUK;
import static nfc.visa.com.nfc.service.TLV.Tag_Aid;
import static nfc.visa.com.nfc.service.TLV.Tag_AppLabel;
import static nfc.visa.com.nfc.service.TLV.Tag_CAP;
import static nfc.visa.com.nfc.service.TLV.Tag_MSD_T2ED;
import static nfc.visa.com.nfc.service.TLV.Tag_PAYWAVE_DF;
import static nfc.visa.com.nfc.service.TLV.Tag_PDOL;
import static nfc.visa.com.nfc.service.TLV.Tag_PPSE_AppLabel;
import static nfc.visa.com.nfc.service.TLV.Tag_PPSE_AppPriorityIndicator;
import static nfc.visa.com.nfc.service.TLV.Tag_PPSE_DF;
import static nfc.visa.com.nfc.service.TLV.Tag_QVSDC_9F10_LEN;
import static nfc.visa.com.nfc.service.TLV.Tag_QVSDC_AC;
import static nfc.visa.com.nfc.service.TLV.Tag_QVSDC_CID;
import static nfc.visa.com.nfc.service.TLV.Tag_QVSDC_CTQ;
import static nfc.visa.com.nfc.service.TLV.Tag_QVSDC_CVN;
import static nfc.visa.com.nfc.service.TLV.Tag_QVSDC_CVR;
import static nfc.visa.com.nfc.service.TLV.Tag_QVSDC_DDLUK;
import static nfc.visa.com.nfc.service.TLV.Tag_QVSDC_DKI;
import static nfc.visa.com.nfc.service.TLV.Tag_QVSDC_DWPI;
import static nfc.visa.com.nfc.service.TLV.Tag_QVSDC_FFI;
import static nfc.visa.com.nfc.service.TLV.Tag_QVSDC_IAD;
import static nfc.visa.com.nfc.service.TLV.Tag_QVSDC_IAD_LEN;
import static nfc.visa.com.nfc.service.TLV.Tag_QVSDC_IDD_FORMAT;
import static nfc.visa.com.nfc.service.TLV.Tag_QVSDC_IDD_PADDING;
import static nfc.visa.com.nfc.service.TLV.Tag_QVSDC_PSN;
import static nfc.visa.com.nfc.service.TLV.Tag_QVSDC_T2ED;

public class VCPCSProcess implements Constants {
    final static short TMPDATABUFFER_Length = 32;
    // Tags to search for within the PDOL
    // DATA DICTIONARY: Processing Options Data Object List, primitive tag '9F38'
    final static short[] PDOL_Tags = {
            (short) 0x9F66,      // Terminal Transaction Qualifiers (4)
            (short) 0x9F02,      // Amount Authorized (6)
            (short) 0x9F03,      // Amount Other (6)
            (short) 0x9F1A,      // Terminal Country Code (2)
            (short) 0x95,        // Terminal Verification Results (5)
            (short) 0x5F2A,      // Transaction Currency Code (2)
            (short) 0x9A,        // Transaction Date (3)
            (short) 0x9C,        // Transaction Type (1)
            (short) 0x9F37,      // Unpredictable Number (4)
    };
    final static byte GPO_DO_TTQ = (byte) 0;  // Terminal Transaction Qualifiers
    final static byte GPO_DO_AMOUNT = (byte) 1;  // Amount Authorized
    final static byte GPO_DO_AMT_OTHER = (byte) 2;  // Amount Other
    final static byte GPO_DO_TERM_CC = (byte) 3;  // Terminal Country Code
    final static byte GPO_DO_TVR = (byte) 4;  // Terminal Verification Results
    final static byte GPO_DO_TRAN_CC = (byte) 5;  // Transaction Currency Code
    final static byte GPO_DO_TRAN_DATE = (byte) 6;  // Transaction Date
    final static byte GPO_DO_TRAN_TYPE = (byte) 7;  // Transaction Type
    final static byte GPO_DO_UNP_NBR = (byte) 8;  // Unpredictable Number
    final static byte GPO_NUMBER_OF_OFFSETS = (byte) 9;
    static short[] GPO_Data_Offsets_CL = new short[GPO_NUMBER_OF_OFFSETS];
    // Response APDUs
    static byte[] SELECT_PPSE_APDU_RESP;                    // PPSE (Proximity Payment System Environment)
    static byte[] SELECT_PPSE_APDU_RESP_DGI9102;            // PPSE (Proximity Payment System Environment)
    static byte[] SELECT_PPSE_APDU_RESP_DGI9102_EMPTY_PPSE;    // PPSE (Proximity Payment System Environment)
    static byte[] SELECT_PAYWAVE_APDU_RESP;                    // Select PAYWAVE
    static byte[] SELECT_PAYWAVE_APDU_RESP_DGI9103;            // Select PAYWAVE
    static byte[] QVSDC_GPO_RESPONSE;                        // QVSDC GPO Response
    static byte[] MSD_GPO_RESPONSE;                            // MSD GPO Response
    static byte[] QVSDC_READRECORD_RESPONSE;                // QVSDC Read Record Response
    static byte[] MSD_READRECORD_RESPONSE;                    // MSD Read Record Response
    static byte CURRENT_PROFILE = 0;
    static byte FirstTime_setDefaultValues = OURFALSE;
    //9F4B SDAD
    static byte supportODA = OURFALSE;
    static byte[] tmpSDADBuffer;  // will be allocated to size of nIC
    static byte SDADsfi = 0;
    static byte SDADrec = 0;
    static short SDADoffset = 0;
    static short SDADlength = 0;
    static byte[] cardUnpredNumber;
    static short CardAuthenRelatedDataoffset = 0;
    static byte locateSDADoffset = OURFALSE;
    static int baseConversion_radix = 16;
    static String dgi8103_modulusN = "";
    static String tag9F47_publicExponentE = "";
    static String dgi8101_privateExponentD = "";
    static String dgi8205_prime1P = "";
    static String dgi8204_prime2Q = "";

    //todo hendy
    //1. cumultaive amount 6.3.5
    //2. number of transaction
    //3. transaction log
    static String dgi8203_exponent1_DmodP1 = "";
    static String dgi8202_exponent2_DmodQ1 = "";
    static String dgi8201_coefficient = "";
    static byte[] RSA_PrimeFactorP;                            // prime factor P
    static byte[] RSA_PrimeFactorQ;                            // prime factor Q
    static byte[] RSA_PrimeExponentP;                        // d mod (p-1)
    static byte[] RSA_PrimeExponentQ;                        // d mod (q-1)

    //Time to live, i.e., the age of the current Account Parameters recognized via the timestamp stored as defined in Req 6.8.
    //Number of transactions, i.e., the number of times a specific set of Account Parameters
    //		(as indexed by YHHHHCC) has been used for a Visa payWave transaction.
    //Cumulative amount, i.e., the cumulative amount of all transactions for a specific set of Account Parameters
    //		(as indexed by YHHHHCC) applicable to a qVSDC transaction only.
    //The number of transactions and/or cumulative amount separate for
    //		international and domestic usage for a qVSDC transaction.
    static byte[] RSA_CRTCoefficient;                        // q-1 mod p
    static byte[] RSA_modulusN;
    static byte[] RSA_publicExponentE;
    static byte[] RSA_privateExponentD;
    static byte[] tmpCryptoDataBuffer;                     // Currently allocating 96 bytes.
    static byte[] tmpDataBuffer;                             // For data passed in and out of methods (16 bytes).
    static int ATC = 0;                                         //Application Transaction Counter, primitive tag '9F36'
    static byte[] CTTA = new byte[BCDLEN];                     //CTTA = Cumulative Total Transaction Amount
    static byte[] gpoCTTA = new byte[BCDLEN];                 //gpoCTTA = temp amount
    static byte[] newCTTA = new byte[BCDLEN];                 //newCTTA = temp amount
    // File system
    static Object[] vsdcRecords;
    static Object[] recordDirectory = new Object[FILE_SYSTEM_DIR_SIZE];
    static short numOfRDEntries;
    static short[] AIP;
    static Object[] AFL;
    static short MS_RecordsOffsetInfo = (short) -1;            // Set from tag 'tag 57', see table 8
    static byte[] decimalizedCrypto_Data;                // This will hold data needed for
    //		the decimalized Cryptogram processing.
    static byte[] t2edWorkdspace;
    static byte[] decimalizedCryptogram = new byte[6];
    static short[] myTL = new short[MYTL_Length];
    static Object[] FCI_PropData_Reg;
    static short totalVisaAID = 0;
    static short PDOL_RelatedDataLength_CL;  // Set when PDOL for contactless is personalized.
    private static short nIC;                                // iccPrivateKey length in bytes
    private static RSAPrivateCrtKey myRSAPrivateCrtKey;    // Chinese Remainder (CRT)

    /**
     * To set default values (in case XML file not present; otherwise, values are overridden by the XML perso file.
     */
    protected static void setDefaultValues() {


        for (short j = 0; j < GPO_NUMBER_OF_OFFSETS; j++) {
            GPO_Data_Offsets_CL[j] = (short) -1;  // Set to -1 if not found in the PDOL.
        }
        if (Tag_QVSDC_9F10_LEN == null) Tag_QVSDC_9F10_LEN = new byte[(short) 1];
        if (Tag_QVSDC_IAD_LEN == null) Tag_QVSDC_IAD_LEN = new byte[(short) 1];
        if (Tag_QVSDC_CVN == null) Tag_QVSDC_CVN = new byte[(short) 1];
        if (Tag_QVSDC_DKI == null) Tag_QVSDC_DKI = new byte[(short) 1];
        if (Tag_QVSDC_CVR == null) Tag_QVSDC_CVR = new byte[CVRLEN];
        if (Tag_QVSDC_DWPI == null) Tag_QVSDC_DWPI = new byte[(short) 4];
        if (Tag_QVSDC_DDLUK == null) Tag_QVSDC_DDLUK = new byte[(short) 4];
        if (Tag_QVSDC_IDD_FORMAT == null) Tag_QVSDC_IDD_FORMAT = new byte[(short) 1];
        if (Tag_QVSDC_IDD_PADDING == null) Tag_QVSDC_IDD_PADDING = new byte[(short) 14];


        Tag_PPSE_AppLabel = new byte[]{(byte) 50, (byte) 0x0A, (byte) 0x56, (byte) 0x49, (byte) 0x53, (byte) 0x41, (byte) 0x20, (byte) 0x44, (byte) 0x45, (byte) 0x42, (byte) 0x49, (byte) 0x54};
        Tag_PPSE_AppPriorityIndicator = new byte[]{(byte) 0x87, (byte) 0x01, (byte) 0x01};

        //DGI 9103
        Tag_AppLabel = new byte[]{(byte) 0x50, (byte) 0x0B, 'V', 'I', 'S', 'A', ' ', 'C', 'R', 'E', 'D', 'I', 'T'};
        Tag_PDOL = new byte[]{(byte) 0x9F, (byte) 0x38, (byte) 0x18,
                (byte) 0x9F, (byte) 0x66, (byte) 0x04,        // Terminal Transaction Qualifiers
                (byte) 0x9F, (byte) 0x02, (byte) 0x06,        // Authorized Amount
                (byte) 0x9F, (byte) 0x03, (byte) 0x06,        // Amount Other
                (byte) 0x9F, (byte) 0x1A, (byte) 0x02,        // Terminal Country Code
                (byte) 0x95, (byte) 0x05,                    // Terminal Verification Results
                (byte) 0x5F, (byte) 0x2A, (byte) 0x02,        // Transaction Currency Code
                (byte) 0x9A, (byte) 0x03,                    // Transaction Date
                (byte) 0x9C, (byte) 0x01,                    // Transaction Type
                (byte) 0x9F, (byte) 0x37, (byte) 0x04};        // Unpredictable Number


        //DGI 9102
        byte[] STORE_DATA_APDU_9102 = new byte[]{
                (byte) 0x80, // CLA (class of command)
                (byte) 0xE2, // INS (instruction);
                (byte) 0x00, // P1  (parameter 1)
                (byte) 0x01, // P2  (parameter 2)
                (byte) 0x25, // LC  (length of data)
                (byte) 0x91, (byte) 0x02, (byte) 0x22,    //DGI 9102
                (byte) 0x6F, (byte) 0x20,                //FCI Template
                (byte) 0x84, (byte) 0x0E, (byte) 0x32, (byte) 0x50, (byte) 0x41, (byte) 0x59, (byte) 0x2E, (byte) 0x53, (byte) 0x59, (byte) 0x53, (byte) 0x2E, (byte) 0x44, (byte) 0x44, (byte) 0x46, (byte) 0x30, (byte) 0x31, //DF Name
                (byte) 0xA5, (byte) 0x0E,                //FCI Proprietary Template
                (byte) 0xBF, (byte) 0x0C, (byte) 0x0B,    //FCI Issuer Discretionary Data
                (byte) 0x61, (byte) 0x09,                //Directory Entry
                (byte) 0x4F, (byte) 0x07, (byte) 0xA0, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x03, (byte) 0x10, (byte) 0x10, //ADF Name
                (byte) 0x00 // LE   (max length of expected result, 0 implies 256)
        };

        //select response empty PPSE
        byte[] SELECT_PPSE_APDU_RESP_DGI9102_EMPTY_PPSE = new byte[]{
                (byte) 0x6F, (byte) 0x15,                //FCI Template
                (byte) 0x84, (byte) 0x0E, (byte) 0x32, (byte) 0x50, (byte) 0x41, (byte) 0x59, (byte) 0x2E, (byte) 0x53, (byte) 0x59, (byte) 0x53, (byte) 0x2E, (byte) 0x44, (byte) 0x44, (byte) 0x46, (byte) 0x30, (byte) 0x31, //DF Name
                (byte) 0xA5, (byte) 0x03,                //FCI Proprietary Template
                (byte) 0xBF, (byte) 0x0C, (byte) 0x00,    //FCI Issuer Discretionary Data
                (byte) 0x09, (byte) 0x00,                //FCI Proprietary Template
        };


        //DGI 9103
        byte[] STORE_DATA_APDU_9103 = new byte[]{
                (byte) 0x80, // CLA (class of command)
                (byte) 0xE2, // INS (instruction);
                (byte) 0x00, // P1  (parameter 1)
                (byte) 0x01, // P2  (parameter 2)
                (byte) 0x38, // LC  (length of data)
                (byte) 0x91, (byte) 0x03, (byte) 0x35,        //DGI 9103
                (byte) 0x6F, (byte) 0x33,                    //FCI Template
                (byte) 0x84, (byte) 0x07, (byte) 0xA0, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x03, (byte) 0x10, (byte) 0x10, //DF Name of selected AID
                (byte) 0xA5, (byte) 0x28,                    //FCI Proprietary Template
                (byte) 0x50, (byte) 0x0B, (byte) 0x56, (byte) 0x49, (byte) 0x53, (byte) 0x41, (byte) 0x20, (byte) 0x43, (byte) 0x52, (byte) 0x45, (byte) 0x44, (byte) 0x49, (byte) 0x54, //Application Label
                (byte) 0x9F, (byte) 0x38, (byte) 0x18,
                (byte) 0x9F, (byte) 0x66, (byte) 0x04,        // PDOL value (Does this request terminal type?)
                (byte) 0x9F, (byte) 0x02, (byte) 0x06,        // Authorized Amount
                (byte) 0x9F, (byte) 0x03, (byte) 0x06,        // Amount Other
                (byte) 0x9F, (byte) 0x1A, (byte) 0x02,        // Terminal Country Code
                (byte) 0x95, (byte) 0x05,                    // Terminal Verification Results
                (byte) 0x5F, (byte) 0x2A, (byte) 0x02,        // Transaction Currency Code
                (byte) 0x9A, (byte) 0x03,                    // Transaction Date
                (byte) 0x9C, (byte) 0x01,                    // Transaction Type
                (byte) 0x9F, (byte) 0x37, (byte) 0x04,            // Unpredictable Number
                (byte) 0x00 // LE   (max length of expected result, 0 implies 256)
        };


        //DGI 9206
        byte[] STORE_DATA_APDU_9206 = new byte[]{
                (byte) 0x80, // CLA (class of command)
                (byte) 0xE2, // INS (instruction);
                (byte) 0x00, // P1  (parameter 1)
                (byte) 0x01, // P2  (parameter 2)
                (byte) 0x0D, // LC  (length of data)
                (byte) 0x92, (byte) 0x06, (byte) 0x0A,
                (byte) 0x82, (byte) 0x02, (byte) 0x00, (byte) 0xC0,
                (byte) 0x94, (byte) 0x04, (byte) 0x08, (byte) 0x01, (byte) 0x01, (byte) 0x00,
                (byte) 0x00 // LE   (max length of expected result, 0 implies 256)
        };


        //DGI 9115
        /*
        byte[] STORE_DATA_APDU_9115 = new byte[] {
	            (byte)0x80, // CLA (class of command)
	            (byte)0xE2, // INS (instruction);
	            (byte)0x00, // P1  (parameter 1)
	            (byte)0x01, // P2  (parameter 2)
	            (byte)0x0D, // LC  (length of data)
	                (byte)0x91, (byte)0x15, (byte)0x0A,
	                (byte)0x82, (byte)0x02, (byte)0x00, (byte)0x00,
	                (byte)0x94, (byte)0x04, (byte)0x08, (byte)0x03, (byte)0x03, (byte)0x00,
	            (byte)0x00 // LE   (max length of expected result, 0 implies 256)
	    };
	    */
        byte[] STORE_DATA_APDU_9115 = new byte[]{
                (byte) 0x80, // CLA (class of command)
                (byte) 0xE2, // INS (instruction);
                (byte) 0x00, // P1  (parameter 1)
                (byte) 0x01, // P2  (parameter 2)
                (byte) 0x69, // LC  (length of data)
                (byte) 0x91, (byte) 0x15, (byte) 0x66,
                (byte) 0x82, (byte) 0x02, (byte) 0x00, (byte) 0x40,
                (byte) 0x94, (byte) 0x04, (byte) 0x08, (byte) 0x03, (byte) 0x03, (byte) 0x00,
                (byte) 0x57, (byte) 0x13, (byte) 0x40, (byte) 0x05, (byte) 0x57, (byte) 0x10, (byte) 0x00, (byte) 0x00, (byte) 0x19, (byte) 0x89, (byte) 0xD1, (byte) 0x51, (byte) 0x02, (byte) 0x21, (byte) 0x55, (byte) 0x55, (byte) 0x53, (byte) 0x33, (byte) 0x00, (byte) 0x34, (byte) 0x1F,
                (byte) 0x5F, (byte) 0x34, (byte) 0x01, (byte) 0x99,
                (byte) 0x9F, (byte) 0x10, (byte) 0x20,
                (byte) 0x1F,
                (byte) 0x43,
                (byte) 0x01,
                (byte) 0x00, (byte) 0x20, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04,
                (byte) 0x04, (byte) 0x30, (byte) 0x00, (byte) 0x01,
                (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x9F, (byte) 0x26, (byte) 0x08, (byte) 0xFE, (byte) 0x2C, (byte) 0xED, (byte) 0xAC, (byte) 0x8C, (byte) 0xFD, (byte) 0xCB, (byte) 0xC8,
                (byte) 0x9F, (byte) 0x27, (byte) 0x01, (byte) 0x80,
                (byte) 0x9F, (byte) 0x36, (byte) 0x02, (byte) 0x00, (byte) 0x00,
                (byte) 0x9F, (byte) 0x6C, (byte) 0x02, (byte) 0x00, (byte) 0x00,
                (byte) 0x9F, (byte) 0x6E, (byte) 0x04, (byte) 0x23, (byte) 0x8C, (byte) 0x00, (byte) 0x00,
                (byte) 0x00 // LE   (max length of expected result, 0 implies 256)
        };


        byte[] STORE_DATA_APDU_9117 = new byte[]{
                (byte) 0x80, // CLA (class of command)
                (byte) 0xE2, // INS (instruction);
                (byte) 0x00, // P1  (parameter 1)
                (byte) 0x01, // P2  (parameter 2)
                (byte) 0x5E, // LC  (length of data)
                (byte) 0x91, (byte) 0x17, (byte) 0x5B,
                (byte) 0x9F, (byte) 0x26, (byte) 0x08, (byte) 0xFE, (byte) 0x2C, (byte) 0xED, (byte) 0xAC, (byte) 0x8C, (byte) 0xFD, (byte) 0xCB, (byte) 0xC8,
                (byte) 0x94, (byte) 0x08, (byte) 0x10, (byte) 0x02, (byte) 0x04, (byte) 0x00, (byte) 0x18, (byte) 0x01, (byte) 0x01, (byte) 0x01,
                (byte) 0x82, (byte) 0x02, (byte) 0x20, (byte) 0x40,
                (byte) 0x9F, (byte) 0x36, (byte) 0x02, (byte) 0x00, (byte) 0x00,
                (byte) 0x9F, (byte) 0x6C, (byte) 0x02, (byte) 0x00, (byte) 0x00,
                (byte) 0x9F, (byte) 0x27, (byte) 0x01, (byte) 0x80,
                (byte) 0x9F, (byte) 0x10, (byte) 0x20,
                (byte) 0x1F,
                (byte) 0x43,
                (byte) 0x01,
                (byte) 0x00, (byte) 0x20, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04,
                (byte) 0x04, (byte) 0x30, (byte) 0x00, (byte) 0x01,
                (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x57, (byte) 0x13, (byte) 0x40, (byte) 0x05, (byte) 0x57, (byte) 0x10, (byte) 0x00, (byte) 0x00, (byte) 0x19, (byte) 0x89, (byte) 0xD1, (byte) 0x51, (byte) 0x02, (byte) 0x21, (byte) 0x55, (byte) 0x55, (byte) 0x53, (byte) 0x33, (byte) 0x00, (byte) 0x34, (byte) 0x1F,
                (byte) 0x00 // LE   (max length of expected result, 0 implies 256)
        };

	/*

	    byte[] STORE_DATA_APDU_9117 = new byte[] {
	            (byte)0x80, // CLA (class of command)
	            (byte)0xE2, // INS (instruction);
	            (byte)0x00, // P1  (parameter 1)
	            (byte)0x01, // P2  (parameter 2)
	            (byte)0x5A, // LC  (length of data)
	            (byte)0x91, (byte)0x17, (byte)0x57,
	            (byte)0x9F, (byte)0x26, (byte)0x08, (byte)0xFE, (byte)0x2C, (byte)0xED, (byte)0xAC, (byte)0x8C, (byte)0xFD, (byte)0xCB, (byte)0xC8,
	            (byte)0x94, (byte)0x04, (byte)0x10, (byte)0x02, (byte)0x04, (byte)0x00,
	            (byte)0x82, (byte)0x02, (byte)0x20, (byte)0x40,
	            (byte)0x9F, (byte)0x36, (byte)0x02, (byte)0x00, (byte)0x00,
	            (byte)0x9F, (byte)0x6C, (byte)0x02, (byte)0x00, (byte)0x00,
	            (byte)0x9F, (byte)0x27, (byte)0x01, (byte)0x80,
	    		(byte)0x9F, (byte)0x10, (byte)0x20,
					(byte)0x1F,
					(byte)0x43,
					(byte)0x01,
					(byte)0x00, (byte)0x20, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
					(byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04,
					(byte)0x04, (byte)0x30, (byte)0x00, (byte)0x01,
					(byte)0x00,
					(byte)0x00,	(byte)0x00,	(byte)0x00,	(byte)0x00,	(byte)0x00,	(byte)0x00,	(byte)0x00,	(byte)0x00,	(byte)0x00,	(byte)0x00,	(byte)0x00,	(byte)0x00,	(byte)0x00,	(byte)0x00,
		        (byte)0x57, (byte)0x13, (byte)0x40, (byte)0x05, (byte)0x57, (byte)0x10, (byte)0x00, (byte)0x00, (byte)0x19, (byte)0x89, (byte)0xD1, (byte)0x51, (byte)0x02, (byte)0x21, (byte)0x55, (byte)0x55, (byte)0x53, (byte)0x33, (byte)0x00, (byte)0x34, (byte)0x1F,
		        (byte)0x00 // LE   (max length of expected result, 0 implies 256)
	    };
	    */

        //DGI 0101
        byte[] STORE_DATA_APDU_0101 = new byte[]{
                (byte) 0x80, // CLA (class of command)
                (byte) 0xE2, // INS (instruction);
                (byte) 0x00, // P1  (parameter 1)
                (byte) 0x01, // P2  (parameter 2)
                (byte) 0x1A, // LC  (length of data)
                (byte) 0x01, (byte) 0x01, (byte) 0x17,
                (byte) 0x70, (byte) 0x15,
                (byte) 0x57, (byte) 0x13, (byte) 0x40, (byte) 0x05, (byte) 0x57, (byte) 0x10, (byte) 0x00, (byte) 0x00, (byte) 0x19, (byte) 0x89, (byte) 0xD1, (byte) 0x51, (byte) 0x02, (byte) 0x21, (byte) 0x55, (byte) 0x55, (byte) 0x53, (byte) 0x33, (byte) 0x00, (byte) 0x34, (byte) 0x1F,
                (byte) 0x00 // LE   (max length of expected result, 0 implies 256)
        };


	    /*
	    //DGI 0103
	    byte[] STORE_DATA_APDU_0103 = new byte[] {
	            (byte)0x80, // CLA (class of command)
	            (byte)0xE2, // INS (instruction);
	            (byte)0x00, // P1  (parameter 1)
	            (byte)0x01, // P2  (parameter 2)
	            (byte)0x10, // LC  (length of data)
	                (byte)0x01, (byte)0x03, (byte)0x0D,
	                (byte)0x70, (byte)0x0B,
	                (byte)0x9F, (byte)0x07, (byte)0x02, (byte)0x00,(byte)0x80,
	                (byte)0x9F, (byte)0x19, (byte)0x03, (byte)0x01,(byte)0x02, (byte)0x03,
	            (byte)0x00 // LE   (max length of expected result, 0 implies 256)
	    };
*/
        //DGI 0103
        byte[] STORE_DATA_APDU_0103 = new byte[]{
                (byte) 0x80, // CLA (class of command)
                (byte) 0xE2, // INS (instruction);
                (byte) 0x00, // P1  (parameter 1)
                (byte) 0x01, // P2  (parameter 2)
                (byte) 0x1C, // LC  (length of data)
                (byte) 0x01, (byte) 0x03, (byte) 0x19,
                (byte) 0x70, (byte) 0x17,
                (byte) 0x9F, (byte) 0x07, (byte) 0x02, (byte) 0x00, (byte) 0x80,
                (byte) 0x9F, (byte) 0x19, (byte) 0x03, (byte) 0x01, (byte) 0x02, (byte) 0x03,
                (byte) 0x9F, (byte) 0x7C, (byte) 0x04, (byte) 0x01, (byte) 0x02, (byte) 0x91, (byte) 0x17,
                (byte) 0x5F, (byte) 0x28, (byte) 0x02, (byte) 0x08, (byte) 0x40,
                (byte) 0x00 // LE   (max length of expected result, 0 implies 256)
        };

        //DGI 3001
        byte[] STORE_DATA_APDU_3001 = new byte[]{
                (byte) 0x80, // CLA (class of command)
                (byte) 0xE2, // INS (instruction);
                (byte) 0x00, // P1  (parameter 1)
                (byte) 0x00, // P2  (parameter 2)
                (byte) 0x0A, // LC  (length of data)
                (byte) 0x30, (byte) 0x01, (byte) 0x07,
                (byte) 0x9F, (byte) 0x68, (byte) 0x04, (byte) 0x10, (byte) 0x00, (byte) 0xA0, (byte) 0x00,
                (byte) 0x00 // LE   (max length of expected result, 0 implies 256)
        };

        //DGI 8000 LIMITED USE KEY
        byte[] STORE_DATA_APDU_8000 = new byte[]{
                (byte) 0x80, // CLA (class of command)
                (byte) 0xE2, // INS (instruction);
                (byte) 0x00, // P1  (parameter 1)
                (byte) 0x00, // P2  (parameter 2)
                (byte) 0x13, // LC  (length of data)
                (byte) 0x80, (byte) 0x00, (byte) 0x10,
                // (byte)0x40, (byte)0x41, (byte)0x42, (byte)0x43,(byte)0x44, (byte)0x45, (byte)0x46,(byte)0x47, (byte)0x48,(byte)0x49,(byte)0x4A,	(byte)0x4B, (byte)0x4C,(byte)0x4D,(byte)0x4E, (byte)0x4F,
                (byte) 0x10, (byte) 0x45, (byte) 0x97, (byte) 0xE5, (byte) 0xA4, (byte) 0xA7, (byte) 0xA7, (byte) 0x73, (byte) 0x08, (byte) 0xFB, (byte) 0x2F, (byte) 0x62, (byte) 0x04, (byte) 0x80, (byte) 0x68, (byte) 0x20,

                (byte) 0x00 // LE   (max length of expected result, 0 implies 256)
        };

        //DGI 8001	ACCOUNT PARAMETERS INDEX
        byte[] STORE_DATA_APDU_8001 = new byte[]{
                (byte) 0x80, // CLA (class of command)
                (byte) 0xE2, // INS (instruction);
                (byte) 0x00, // P1  (parameter 1)
                (byte) 0x00, // P2  (parameter 2)
                (byte) 0x0A, // LC  (length of data)
                (byte) 0x80, (byte) 0x01, (byte) 0x07,
                (byte) 0x04, (byte) 0x03, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01,
                (byte) 0x00 // LE   (max length of expected result, 0 implies 256)
        };

        //DGI 8201, 8202, 8203, 8204, 8205
        RSAPrivateCrtKeySpec caPrivKeySpec = new RSAPrivateCrtKeySpec(
                new BigInteger("b259d2d6e627a768c94be36164c2d9fc79d97aab9253140e5bf17751197731d6f7540d2509e7b9ffee0a70a6e26d56e92d2edd7f85aba85600b69089f35f6bdbf3c298e05842535d9f064e6b0391cb7d306e0a2d20c4dfb4e7b49a9640bdea26c10ad69c3f05007ce2513cee44cfe01998e62b6c3637d3fc0391079b26ee36d5", 16),    //MODULUS N
                new BigInteger("11", 16),    //PUBLIC EXPONENT E
                new BigInteger("92e08f83cc9920746989ca5034dcb384a094fb9c5a6288fcc4304424ab8f56388f72652d8fafc65a4b9020896f2cde297080f2a540e7b7ce5af0b3446e1258d1dd7f245cf54124b4c6e17da21b90a0ebd22605e6f45c9f136d7a13eaac1c0f7487de8bd6d924972408ebb58af71e76fd7b012a8d0e165f3ae2e5077a8648e619", 16), //PRIVATE EXPONENT D
                new BigInteger("EA5A71FCE5047001BA6882A899632A2703EDB2A5EB6A5CBD3F6D59D4068F03186162C3C20AD926EA9B7CAB0A9F3424255A2F54BEFF922B5A7DF4D9E92A4315258000000000000000", 16), //PRIME_P, SETP (DGI-8205)
                new BigInteger("C92B822028008D31D4626370F52AC671728C717132224D02F1F4BAD1280DC60745D5CE3D6CB86DBF4335425282D7A5384BAE26D8CD7361A066E1C20D2A05DEF38000000000000000", 16), //PRIME_Q, SETQ (DGI-8204)
                new BigInteger("9C3C4BFDEE02F5567C45AC7066421C1A029E7719479C3DD37F9E3BE2AF0A021040EC82815C90C49C67A8720714CD6D6E3C1F8DD4AA61723C53F891461C2CB8C38000000000000000", 16), //PRIME_EXPONENT_P, SETDP1 (DGI-8203)
                new BigInteger("861D016AC555B3768D96ECF5F8C72EF64C5DA0F6216C33574BF87C8B70092EAF83E3DED39DD0492A2CCE2C3701E518D0327419E5DE4CEBC04496815E1C03E9F78000000000000000", 16), //PRIME_EXPONENT_Q, SETDQ1 (DGI-8202)
                new BigInteger("588C13E98E5294BE0161E432F8B0E77A208D8AAC95A7D8091099AFEC687A72A59C0CB179A327DFB044F0BFAA21D6232E0C29C99BBAD8A735B3952007F49DF43C8000000000000000", 16)); //CRT_COEFFICIENT, SETPQ  (DGI-8201)
/*
        RSAPrivateCrtKeySpec   caPrivKeySpec = new RSAPrivateCrtKeySpec(
                new BigInteger("b259d2d6e627a768c94be36164c2d9fc79d97aab9253140e5bf17751197731d6f7540d2509e7b9ffee0a70a6e26d56e92d2edd7f85aba85600b69089f35f6bdbf3c298e05842535d9f064e6b0391cb7d306e0a2d20c4dfb4e7b49a9640bdea26c10ad69c3f05007ce2513cee44cfe01998e62b6c3637d3fc0391079b26ee36d5", 16), //MODULUS N
                new BigInteger("11", 16), //PUBLIC EXPONENT E
                new BigInteger("92e08f83cc9920746989ca5034dcb384a094fb9c5a6288fcc4304424ab8f56388f72652d8fafc65a4b9020896f2cde297080f2a540e7b7ce5af0b3446e1258d1dd7f245cf54124b4c6e17da21b90a0ebd22605e6f45c9f136d7a13eaac1c0f7487de8bd6d924972408ebb58af71e76fd7b012a8d0e165f3ae2e5077a8648e619", 16), //PRIVATE EXPONENT D
                new BigInteger("EA5A71FCE5047001BA6882A899632A2703EDB2A5EB6A5CBD3F6D59D4068F03186162C3C20AD926EA9B7CAB0A9F3424255A2F54BEFF922B5A7DF4D9E92A4315258000000000000000", 16),		//PRIME_P, SETP (DGI-8205)
                new BigInteger("C92B822028008D31D4626370F52AC671728C717132224D02F1F4BAD1280DC60745D5CE3D6CB86DBF4335425282D7A5384BAE26D8CD7361A066E1C20D2A05DEF38000000000000000", 16),		//PRIME_Q, SETQ (DGI-8204)
                new BigInteger("9C3C4BFDEE02F5567C45AC7066421C1A029E7719479C3DD37F9E3BE2AF0A021040EC82815C90C49C67A8720714CD6D6E3C1F8DD4AA61723C53F891461C2CB8C38000000000000000", 16),		//PRIME_EXPONENT_P, SETDP1 (DGI-8203)
                new BigInteger("861D016AC555B3768D96ECF5F8C72EF64C5DA0F6216C33574BF87C8B70092EAF83E3DED39DD0492A2CCE2C3701E518D0327419E5DE4CEBC04496815E1C03E9F78000000000000000", 16),		//PRIME_EXPONENT_Q, SETDQ1 (DGI-8202)
                new BigInteger("588C13E98E5294BE0161E432F8B0E77A208D8AAC95A7D8091099AFEC687A72A59C0CB179A327DFB044F0BFAA21D6232E0C29C99BBAD8A735B3952007F49DF43C8000000000000000", 16));	//CRT_COEFFICIENT, SETPQ  (DGI-8201)
  */

        //Simulate XML file
        final String XML_AP_AccountParametersIndex = "04030000000001";        //YHHHHCC=4300001
        final String XML_AP_T2ED = "00000000";
        final String XML_AP_LUK = "404142434445464748494A4B4C4D4E4F";
        final String XML_APR_AccountParametersIndex = "04030000000001";    //YHHHHCC=4300001
        //04 03 00 00 00 00 01
        final String XML_APR_SequenceCounter = "01";
        final String XML_APR_Transaction_Log = "00000000";
        final String XML_APR_MAC = "0000000000000000";
        final String XML_PPSE_AID = "840E325041592e5359532e4444463031";        //'2', 'P', 'A', 'Y', '.', 'S', 'Y', 'S', '.', 'D', 'D', 'F', '0', '1'};
        //final String XML_VBCPA_AID = "8407A0000000032010"; 				//if using MSD reader
        final String XML_VBCPA_AID = "8407A0000000031010";                    //If using qVSDC reader
        final String XML_ACP_CVM = "9F680400000000";
        final String XML_ACP_MSDSupport = "01";
        final String XML_ACP_DKI = "01";

        AccountParameters.setAccountParametersIndex(XML_AP_AccountParametersIndex);
        AccountParameters.setT2ED(XML_AP_T2ED);
        AccountParameters.setLUK(XML_AP_LUK);
        AccountParametersReplenishment.setAccountParametersIndex(XML_APR_AccountParametersIndex);
        AccountParametersReplenishment.setSequenceCounter(XML_APR_SequenceCounter);
        AccountParametersReplenishment.setTransactionLog(XML_APR_Transaction_Log);
        AccountParametersReplenishment.setMAC(XML_APR_MAC);
        AccountConfigurationParameters.setPPSEAID(XML_PPSE_AID);
        AccountConfigurationParameters.setPAYWAVEAID(XML_VBCPA_AID);
        AccountConfigurationParameters.setCVM(XML_ACP_CVM);
        AccountConfigurationParameters.setMSDSupport(XML_ACP_MSDSupport);
        AccountConfigurationParameters.setDKI(XML_ACP_DKI);

        Tag_PPSE_DF = AccountConfigurationParameters.getPPSEAID();
        Tag_PAYWAVE_DF = AccountConfigurationParameters.getPAYWAVEAID();
        Tag_Aid = AccountConfigurationParameters.getPAYWAVEAID();


        //Personalization of HCE PayWave
        storeData(STORE_DATA_APDU_9102, (short) 0, (short) STORE_DATA_APDU_9102.length);    //perso PPSE
        storeData(STORE_DATA_APDU_9103, (short) 0, (short) STORE_DATA_APDU_9103.length);    //perso PayWave

        storeData(STORE_DATA_APDU_9206, (short) 0, (short) STORE_DATA_APDU_9206.length);    //perso MSD
        storeData(STORE_DATA_APDU_9115, (short) 0, (short) STORE_DATA_APDU_9115.length);    //perso qVSDC online wo oda
        storeData(STORE_DATA_APDU_9117, (short) 0, (short) STORE_DATA_APDU_9117.length);    //perso qVSDC online with oda

        storeData(STORE_DATA_APDU_0101, (short) 0, (short) STORE_DATA_APDU_0101.length);    //record SFI-1 record-1 MSD
        storeData(STORE_DATA_APDU_0103, (short) 0, (short) STORE_DATA_APDU_0103.length);    //record SFI-1 record-3 qVSDC
        storeData(STORE_DATA_APDU_3001, (short) 0, (short) STORE_DATA_APDU_3001.length);    //Application Internal Data
        storeData(STORE_DATA_APDU_8000, (short) 0, (short) STORE_DATA_APDU_8000.length);    //LUK
        storeData(STORE_DATA_APDU_8001, (short) 0, (short) STORE_DATA_APDU_8001.length);    //Account Parameters Index

        decimalizedCryptogramSetup();

        //locateSDADrecord(); 		//todo hendy

        FirstTime_setDefaultValues = OURTRUE;
    }


    /********************************
     **                            **
     ** File System Implementation
     **                            **
     *******************************/

    /**
     * @param SFI
     * @param recNo
     * @return
     */
    private static byte[] getRecord(byte SFI, byte recNo) {
        byte[] record = null;

        short localRecno = findRecord((byte) SFI, (byte) recNo);
        if (localRecno != -1) {
            record = (byte[]) (vsdcRecords[localRecno]);
        }
        return record;
    }


    /**
     * @param SFI
     * @param recNo
     * @param asQuery
     * @return
     */
    private static short findRecord(byte SFI, byte recNo) {
        if (vsdcRecords == null)
            return -1;

        byte[] entry;
        byte localSFI = 0;
        byte localREC = 0;
        for (short i = 0; (i < 32) && (recordDirectory[i] != null); i++) {
            entry = (byte[]) (recordDirectory[i]);
            localSFI = entry[0];
            localREC = entry[1];
            if ((localSFI == SFI) && (localREC == recNo))
                return i;
        }

        return -1;
    }


    /**
     * @param SFI
     * @param recNo
     */
    private static void placeInDirectory(byte SFI, byte recNo) {
        byte[] entry;
        for (byte i = 0; i < 32; i++) {
            if (recordDirectory[i] == null) {
                entry = new byte[2];
                entry[0] = SFI;
                entry[1] = recNo;
                recordDirectory[i] = entry;
                numOfRDEntries = (byte) (i + 1);
                return;
            }
        }
    }


    /**
     * Helper Function for storeTagValue()
     *
     * @param data
     * @param offset
     * @param t
     * @param len
     * @return
     */
    private static byte[] setData(byte[] data, short offset, byte[] t, short len) {
        if (t == null)
            t = new byte[len];

        Util.arrayCopy(data, offset, t, (short) 0, len);

        return t;
    }

    /**
     * Handler for individual tag elements
     *
     * @param tag
     * @param data
     * @param offset
     * @param length
     */
    private static void storeTagValue(short tag, byte[] data, short offset, short length) {
        byte currbyte = data[offset];

        switch (tag) {
            case (short) 0x0082: // AIP
                length = Util.getShort(data, offset);    //value of AIP

                if (AIP == null)
                    AIP = new short[NUM_OF_PROFILES];
                AIP[(short) CURRENT_PROFILE] = length;

                return;

            case (short) 0x0094:  // AFL
                //      if ((length % 4) != 0)
                //      ISOException.throwIt(ISO7816.SW_WRONG_DATA);

                if (AFL == null)
                    AFL = new Object[NUM_OF_PROFILES];
                byte localIndex = CURRENT_PROFILE;

                AFL[localIndex] = new byte[length];
                byte[] localAFLptr = ((byte[]) (AFL[localIndex]));

                //value of AFL
                Util.arrayCopy(data, offset, localAFLptr, (short) 0, length);


                short numOfQuads = (short) (localAFLptr.length / 4);
                byte localSFI = (byte) 0;
                byte localRecNo = (byte) 0;
                byte firstRec = (byte) 0;
                byte lastRec = (byte) 0;
                ;
                short index = (short) 0;

                for (short j = 0; j < numOfQuads; j++) {
                    index = (short) (j * 4);
                    firstRec = localAFLptr[(short) (index + 1)];
                    lastRec = localAFLptr[(short) (index + 2)];
                    localSFI = (byte) ((localAFLptr[index] >> 3) & 0x1F);

                    for (localRecNo = firstRec; localRecNo <= lastRec; localRecNo++) {
                        //create record for SFI and Record
                        placeInDirectory(localSFI, localRecNo);
                        if ((decimalizedCrypto_Data == null)
                                &&
                                (CURRENT_PROFILE == PROFILE_MSD)
                                &&
                                ((localSFI == (byte) 1) && ((localRecNo == (byte) 1) || (localRecNo == (byte) 2)))
                                ) {
                            //dCVV or Decimalized Cryptogram
                            decimalizedCrypto_Data = new byte[DCRYPTO_DATASIZE];
                            decimalizedCrypto_Data[DCRYPTO_TRACK2_SFI] = localSFI;
                            decimalizedCrypto_Data[DCRYPTO_TRACK2_REC] = localRecNo;
                        }
                    }
                }
                break;



	   /*
            case (short)0x4F:  //ADF Name
            	Tag_Aid = setData(data, offset, Tag_Aid, length);
	    	    //AccountConfigurationParameters.setVBCPAAID(Util.getString(Tag_Aid));
            	return;

            case (short)0x50:  //Application Label
            	Tag_PPSE_AppLabel = setData(data, offset, Tag_PPSE_AppLabel, length);
            	return;

            case (short)0x87:  //Application Priority Indicator
            	Tag_PPSE_AppPriorityIndicator = setData(data, offset, Tag_PPSE_AppPriorityIndicator, length);
            	return;

            case (short)0x9F2A:  //Kernel Identifier
            	Tag_Kernel_Identifier = setData(data, offset, Tag_Kernel_Identifier, length);
            	return;
     */

            case (short) 0x9F68:  // Card Additional Processes
                Tag_CAP = setData(data, offset, Tag_CAP, (short) 4);
                break;

            case (short) 0x0057:  // Track 2 Equivalent Data
                if (CURRENT_PROFILE == PROFILE_MSD)
                    Tag_MSD_T2ED = setData(data, offset, Tag_MSD_T2ED, length);

                if ((CURRENT_PROFILE == PROFILE_QVSDC_ONLINE_WO_ODA) || (CURRENT_PROFILE == PROFILE_QVSDC_ONLINE_WITH_ODA))
                    Tag_QVSDC_T2ED = setData(data, offset, Tag_QVSDC_T2ED, length);
                return;

            case (short) 0x5F34:    //Application PAN Sequence Number
                Tag_QVSDC_PSN = setData(data, offset, Tag_QVSDC_PSN, (short) 1);
                break;

            case (short) 0x9F10:
                //Tag_QVSDC_IAD = setData(data, offset, Tag_QVSDC_IAD, (short)0x1F);
                Tag_QVSDC_IAD = setData(data, offset, Tag_QVSDC_IAD, length);

                //	9F10  20
                //		  1F   							IAD LENGTH
                //		  43 							CVN
                //		  01 							DKI
                //		  002000000000 					CVR
                //		  01020304 						DIGITAL WALLET ID
                //        04300001 						DERIVATION DATA
                //		  00							IDD FORMAT
                //        00 00 00 00 00 00 00 00 00 00 00 00 00 00 	IDD PADDING
                Tag_QVSDC_9F10_LEN[0] = (byte) length;
                //Tag_QVSDC_IAD_LEN[0]=(byte)Tag_QVSDC_IAD[(short)0]; offset++;
                Util.arrayCopy(data, offset, Tag_QVSDC_IAD_LEN, (short) 0, (short) 1);
                offset++;
                Util.arrayCopy(data, offset, Tag_QVSDC_CVN, (short) 0, (short) 1);
                offset++;
                Util.arrayCopy(data, offset, Tag_QVSDC_DKI, (short) 0, (short) 1);
                offset++;
                Util.arrayCopy(data, offset, Tag_QVSDC_CVR, (short) 0, (short) 6);
                offset += 6;
                Util.arrayCopy(data, offset, Tag_QVSDC_DWPI, (short) 0, (short) 4);
                offset += 4;
                Util.arrayCopy(data, offset, Tag_QVSDC_DDLUK, (short) 0, (short) 4);
                offset += 4;
                Util.arrayCopy(data, offset, Tag_QVSDC_IDD_FORMAT, (short) 0, (short) 1);
                offset++;
                Util.arrayCopy(data, offset, Tag_QVSDC_IDD_PADDING, (short) 0, (short) 14);
                offset += 14;

                break;

            case (short) 0x9F26:
                Tag_QVSDC_AC = setData(data, offset, Tag_QVSDC_AC, (short) 8);
                break;

            case (short) 0x9F27:
                Tag_QVSDC_CID = setData(data, offset, Tag_QVSDC_CID, (short) 1);
                break;

            case (short) 0x9F36:  // ATC
                ATC = (int) (Util.getShort(data, offset) & 0xFFFF);
                break;

            case (short) 0x9F6C:  // Card Transaction Qualifiers
                Tag_QVSDC_CTQ = setData(data, offset, Tag_QVSDC_CTQ, (short) 2);
                break;

            case (short) 0x9F6E:  // Form Factor Indicator
                Tag_QVSDC_FFI = setData(data, offset, Tag_QVSDC_FFI, (short) 4);
                break;


            default:
                break;
        }
    }


    /**
     * Handler for Store Data commands
     *
     * @param inBuffer
     * @param inOffset
     * @param inLength
     */
    protected static byte[] storeData(byte[] inBuffer, short inOffset, short inLength) {
        short offset, span;
        byte[] storeData_responseApdu = new byte[2];
        byte[] record;
        int returnVal = 0;

        short dgi = Util.getShort(inBuffer, (short) (inOffset + OFFSET_CDATA));
        short len = (short) (inBuffer[(short) (inOffset + OFFSET_CDATA + 2)] & 0xff);
        short dgiDataOffset = (short) (inOffset + STOREDATA_DATA_OFFSET);

        short hiByteOfDGI = (short) ((short) (dgi >> 8) & (short) 0x00FF);
        short loByteOfDGI = (short) (dgi & (short) 0x00FF);

        Util.arrayCopy(ISO7816_SW_NO_ERROR, (short) 0, storeData_responseApdu, (short) 0, (short) ISO7816_SW_NO_ERROR.length);

        if ((hiByteOfDGI >= (short) 0x01) && (hiByteOfDGI <= (short) 0x1E)) // This must be a record
        {
            if (vsdcRecords == null) {
                vsdcRecords = new Object[numOfRDEntries];
            }

            short localRecno = findRecord((byte) hiByteOfDGI, (byte) loByteOfDGI);
            if (localRecno != -1) {
                record = new byte[len];
                Util.arrayCopy(inBuffer, dgiDataOffset, record, (short) 0, len);
                vsdcRecords[localRecno] = record;
            }

            /*
            byte[] record = (byte[])(vsdcRecords[findRecord((byte)hiByteOfDGI, (byte)loByteOfDGI, false)]);
            if (record == null)
            {
            	//if record not found then insert new record
                record = new byte[len];
                Util.arrayCopy(inBuffer, dgiDataOffset, record, (short)0, len);
                vsdcRecords[findRecord((byte)hiByteOfDGI, (byte)loByteOfDGI, false)] = record;
            }
            else
            {
                byte[] newrecord =  new byte[len];
                Util.arrayCopy(inBuffer, dgiDataOffset, newrecord, (short)0, len);
                vsdcRecords[findRecord((byte)hiByteOfDGI, (byte)loByteOfDGI, false)] = newrecord;
            }
            */

        } else {
            switch (dgi) {
                case (short) 0x9102:    //select PPSE response

        		/*
					*Store Data DGI 9102
					* 80 E2 00 01 32 											Store Data
					* 91 02 2F 													DGI 9102
					*	6F 2D													FCI Template
					*		84 0E 												DF Name
					*			32 50 41 59 2E 53 59 53 2E 44 44 46 30 31
					*		A5 1B 												FCI Proprietary Template
					*			BF 0C 18 										FCI Issuer Discretionary Data
					*				61 16 										Directory Entry
					*					4F 07 A0 00 00 00 03 10 10 				ADF Name
					*					50 0B 56 49 53 41 20 43 52 45 44 49 54 	Application Label
					*					87 01 01 								Application Priority Indicator
					*					9F 2A 08 01 02 03 04 05 06 07 08 		Kernel Identifier
					*
				*/

                    //todo add hendy add 50 , 87, 9F2A
                    if (inBuffer[PPSE_FCI_TEMPLATE_OFFSET] != FCI_TEMPLATE)            //tag '6F' FCI Template
                        Util.arrayCopy(ISO7816_SW_WRONG_DATA, (short) 0, storeData_responseApdu, (short) 0, (short) ISO7816_SW_WRONG_DATA.length);

                    if (inBuffer[PPSE_DF_NAME_OFFSET] != (byte) 0x84)                    //tag '84' DF Name
                        Util.arrayCopy(ISO7816_SW_WRONG_DATA, (short) 0, storeData_responseApdu, (short) 0, (short) ISO7816_SW_WRONG_DATA.length);

                    if (inBuffer[PPSE_FCI_PROPRIETARY_TEMPLATE_OFFSET] != (byte) 0xA5)    //tag 'A5' FCI PROPRIETARY TEMPLATE
                        Util.arrayCopy(ISO7816_SW_WRONG_DATA, (short) 0, storeData_responseApdu, (short) 0, (short) ISO7816_SW_WRONG_DATA.length);

                    if (inBuffer[PPSE_DIRECTORY_ENTRY_OFFSET] != (byte) 0x61)            //tag '61' DIRECTORY_ENTRY
                        Util.arrayCopy(ISO7816_SW_WRONG_DATA, (short) 0, storeData_responseApdu, (short) 0, (short) ISO7816_SW_WRONG_DATA.length);

                    len = inBuffer[(short) (PPSE_FCI_TEMPLATE_OFFSET - 1)];
                    SELECT_PPSE_APDU_RESP_DGI9102 = new byte[(short) (len + 2)];  //data+SW
                    Util.arrayCopy(inBuffer, PPSE_FCI_TEMPLATE_OFFSET, SELECT_PPSE_APDU_RESP_DGI9102, (short) 0, len);

                    Util.arrayCopy(inBuffer, (short) (PPSE_DF_NAME_OFFSET + 2), Tag_PPSE_DF, (short) 0, (short) (PPSE_DF_NAME_OFFSET + 1));
                    // AccountConfigurationParameters.setPPSEAID(Util.getString(Tag_PPSE_DF));

                    len = inBuffer[(short) (PPSE_DIRECTORY_ENTRY_OFFSET + 1)];
                    dgiDataOffset = (short) (PPSE_DIRECTORY_ENTRY_OFFSET + 2);


                    break;

                case (short) 0x9103: //select PAYWAVE response
        		/*
	        		* Store Data DGI 9103
	        		* 80 E2 00 01 38 Store Data
	        		* 91 03 35 	DGI 9103
	        		*	6F 33	FCI Template
	        		*		84 07 	DF Name (selected AID)
	        		*			A0 00 00 00 03 10 10
	        		*		A5 28 	FCI Proprietary Template
	        		*			50 0B 56 49 53 41 20 43 52 45 44 49 54 Application Label
	        		*			9F 38 18 PDOL
	        		*			  	 9F66 04 TTQ
	        		*			  	 9F02 06 Authorized Amount
	        		*			 	 9F03 06 Amount Other
	        		*				 9F1A 02 Terminal Country Code
	        		*			 	 95   05 Terminal Verification Results
	        		*			 	 5F2A 02 Tansaction Currency Code
	        		*				 9A   03 Transaction Date
	        		*				 9C   01 Transaction Type
	        		*				 9F37 04 Unpredictable Number
	        		*
	        		*
        		*/
                    //todo hendy add 9F5A and 5F2D
                    //todo about error handling
                    if (inBuffer[PAYWAVE_FCI_TEMPLATE_OFFSET] != FCI_TEMPLATE)            //tag '6F' FCI Template
                        Util.arrayCopy(ISO7816_SW_WRONG_DATA, (short) 0, storeData_responseApdu, (short) 0, (short) ISO7816_SW_WRONG_DATA.length);

                    if (inBuffer[PAYWAVE_DF_NAME_OFFSET] != (byte) 0x84)                    //tag '84' DF Name
                        Util.arrayCopy(ISO7816_SW_WRONG_DATA, (short) 0, storeData_responseApdu, (short) 0, (short) ISO7816_SW_WRONG_DATA.length);

                    if (inBuffer[PAYWAVE_FCI_PROPRIETARY_TEMPLATE_OFFSET] != (byte) 0xA5)    //tag 'A5' FCI PROPRIETARY TEMPLATE
                        Util.arrayCopy(ISO7816_SW_WRONG_DATA, (short) 0, storeData_responseApdu, (short) 0, (short) ISO7816_SW_WRONG_DATA.length);

                    len = inBuffer[(short) (PAYWAVE_FCI_TEMPLATE_OFFSET - 1)];
                    SELECT_PAYWAVE_APDU_RESP_DGI9103 = new byte[(short) (len + 2)];  //data+SW
                    Util.arrayCopy(inBuffer, PAYWAVE_FCI_TEMPLATE_OFFSET, SELECT_PAYWAVE_APDU_RESP_DGI9103, (short) 0, len);

                    //starting buffer tag '6F'
                    //starting offset at 11 tag 'A5'
                    returnVal = getGPO_PDOLdataOffsets((byte[]) SELECT_PAYWAVE_APDU_RESP_DGI9103, (short) 11, (short) (SELECT_PAYWAVE_APDU_RESP_DGI9103.length - 2));

                    len = (short) 0;    //skip parseDOL
                    dgiDataOffset = inLength;
                    break;

                case (short) 0x8000:    //LUK (16 bytes)
                    //80 E2 00 00 33 80 00 30 #KeyEncrypt104597E5A4A7A77308FB2F6204806820# #KeyEncrypt94FB8AD6AEFD26F7FD767A527929021C# #KeyEncrypt6143CEAED038AE73C7E352D945F7765D# ::
                    //					      10 45 97 E5 A4 A7 A7 73 08 FB 2F 62 04 80 68 20
                    //80 E2 00 00 33 80 00 30 10 45 97 E5 A4 A7 A7 73 08 FB 2F 62 04 80 68 20 94 FB 8A D6 AE FD 26 F7 FD 76 7A 52 79 29 02 1C 61 43 CE AE D0 38 AE 73 C7 E3 52 D9 45 F7 76 5D"

                    if (len != (short) 16)
                        Util.arrayCopy(ISO7816_SW_WRONG_DATA, (short) 0, storeData_responseApdu, (short) 0, (short) ISO7816_SW_WRONG_DATA.length);

                    if (Tag_ACCOUNT_PARAMETERS_LUK == null)
                        Tag_ACCOUNT_PARAMETERS_LUK = new byte[(short) 16];

                    // Tag_AP_LUK
                    // UDK: Unique DEA Key (LIMITED USE KEY)


                    Util.arrayCopy(inBuffer, dgiDataOffset, Tag_ACCOUNT_PARAMETERS_LUK, (short) 0, len);
                    //AccountConfigurationParameters.setVBCPAAID(Util.getString(Tag_Aid));
                    //AccountParameters.setLUK(XML_AP_LUK);

                    len = (short) 0;        //skip parseDOL
                    break;

                case (short) 0x8001: //Account Parameters Index (7 bytes)
                    //80 E2 00 00 0A 80 01 07 04 03 00 00 00 00 01
                    //04 03 00 00 00 00 01  		//YHHHHCC=4300001

                    if (len != (short) 7)
                        Util.arrayCopy(ISO7816_SW_WRONG_DATA, (short) 0, storeData_responseApdu, (short) 0, (short) ISO7816_SW_WRONG_DATA.length);

                    if (Tag_ACCOUNT_PARAMETERS_INDEX == null)
                        Tag_ACCOUNT_PARAMETERS_INDEX = new byte[(short) 7];

                    Util.arrayCopy(inBuffer, dgiDataOffset, Tag_ACCOUNT_PARAMETERS_INDEX, (short) 0, len);

                    len = (short) 0;        //skip parseDOL
                    break;

                case (short) 0x8101:
                case (short) 0x8103:
                    //short len1 = Util.calcKeyLength(inBuffer, dgiDataOffset, len);
                    //nIC = (short)(len);		//96 = 48 * 2			//768 = 96 * 8
                    //112 = 56 * 2		//896 = 112 * 8
                    //128 = 64 * 2		//1024 = 128 * 8


                    //String dgi8103_modulusN
                    //String tag9F47_publicExponentE
                    //String dgi8101_privateExponentD


                    switch (loByteOfDGI) {
                        case (short) 0x01:
                            if (RSA_privateExponentD == null)
                                RSA_privateExponentD = new byte[(short) len];
                            Util.arrayCopy(inBuffer, dgiDataOffset, RSA_privateExponentD, (short) 0, len);
                            dgi8101_privateExponentD = Util.byteArrayToHex(RSA_privateExponentD);
                            break;
                        case (short) 0x03:
                            if (RSA_modulusN == null)
                                RSA_modulusN = new byte[(short) len];
                            Util.arrayCopy(inBuffer, dgiDataOffset, RSA_modulusN, (short) 0, len);
                            dgi8103_modulusN = Util.byteArrayToHex(RSA_modulusN);
                            break;
                    }
                    len = (short) 0;        //skip parseDOL
                    break;

                case (short) 0x8201:
                case (short) 0x8202:
                case (short) 0x8203:
                case (short) 0x8204:
                case (short) 0x8205:

                    short len2 = Util.calcKeyLength(inBuffer, dgiDataOffset, len);
                    nIC = (short) (len * 2);   //96 = 48 * 2		//768 = 96 * 8
                    //112 = 56 * 2		//896 = 112 * 8
                    //128 = 64 * 2		//1024 = 128 * 8

                    //todo if (((nIC % 4) != 0) || (nIC < (short)64) || (nIC >= (short)248))
                    //todo 	   ISOException.throwIt(ISO7816.SW_WRONG_DATA);

                    if (tmpSDADBuffer == null)
                        tmpSDADBuffer = new byte[(short) nIC];

                    switch (loByteOfDGI) {
                        case (short) 0x01: // q-1 mod p
                            //myRSAPrivateCrtKey.setPQ(inBuffer, dgiDataOffset, len);
                            if (RSA_CRTCoefficient == null)
                                RSA_CRTCoefficient = new byte[(short) len];
                            Util.arrayCopy(inBuffer, dgiDataOffset, RSA_CRTCoefficient, (short) 0, len);
                            dgi8201_coefficient = Util.byteArrayToHex(RSA_CRTCoefficient);
                            break;

                        case (short) 0x02: // d mod (q - 1)
                            //myRSAPrivateCrtKey.setDQ1(inBuffer, dgiDataOffset, len);
                            if (RSA_PrimeExponentQ == null)
                                RSA_PrimeExponentQ = new byte[(short) len];
                            Util.arrayCopy(inBuffer, dgiDataOffset, RSA_PrimeExponentQ, (short) 0, len);
                            dgi8202_exponent2_DmodQ1 = Util.byteArrayToHex(RSA_PrimeExponentQ);
                            break;

                        case (short) 0x03: // d mod (p - 1)
                            //myRSAPrivateCrtKey.setDP1(inBuffer, dgiDataOffset, len);
                            if (RSA_PrimeExponentP == null)
                                RSA_PrimeExponentP = new byte[(short) len];
                            Util.arrayCopy(inBuffer, dgiDataOffset, RSA_PrimeExponentP, (short) 0, len);
                            dgi8203_exponent1_DmodP1 = Util.byteArrayToHex(RSA_PrimeExponentP);
                            break;

                        case (short) 0x04: // prime factor q
                            //myRSAPrivateCrtKey.setQ(inBuffer, dgiDataOffset, len);
                            if (RSA_PrimeFactorQ == null)
                                RSA_PrimeFactorQ = new byte[(short) len];
                            Util.arrayCopy(inBuffer, dgiDataOffset, RSA_PrimeFactorQ, (short) 0, len);
                            dgi8204_prime2Q = Util.byteArrayToHex(RSA_PrimeFactorQ);
                            break;

                        case (short) 0x05: // prime factor p
                            //myRSAPrivateCrtKey.setP(inBuffer, dgiDataOffset, len);
                            if (RSA_PrimeFactorP == null)
                                RSA_PrimeFactorP = new byte[(short) len];
                            Util.arrayCopy(inBuffer, dgiDataOffset, RSA_PrimeFactorP, (short) 0, len);
                            dgi8205_prime1P = Util.byteArrayToHex(RSA_PrimeFactorP);
                            break;
                    }


            	 /*
            	  //
                  // ca keys
                  //
                  RSAPublicKeySpec caPubKeySpec = new RSAPublicKeySpec(
                      new BigInteger("b259d2d6e627a768c94be36164c2d9fc79d97aab9253140e5bf17751197731d6f7540d2509e7b9ffee0a70a6e26d56e92d2edd7f85aba85600b69089f35f6bdbf3c298e05842535d9f064e6b0391cb7d306e0a2d20c4dfb4e7b49a9640bdea26c10ad69c3f05007ce2513cee44cfe01998e62b6c3637d3fc0391079b26ee36d5", 16),
                      new BigInteger("11", 16));

                  RSAPrivateCrtKeySpec   caPrivKeySpec = new RSAPrivateCrtKeySpec(
                      new BigInteger("b259d2d6e627a768c94be36164c2d9fc79d97aab9253140e5bf17751197731d6f7540d2509e7b9ffee0a70a6e26d56e92d2edd7f85aba85600b69089f35f6bdbf3c298e05842535d9f064e6b0391cb7d306e0a2d20c4dfb4e7b49a9640bdea26c10ad69c3f05007ce2513cee44cfe01998e62b6c3637d3fc0391079b26ee36d5", 16), //MODULUS N
                      new BigInteger("11", 16), //PUBLIC EXPONENT E
                      new BigInteger("92e08f83cc9920746989ca5034dcb384a094fb9c5a6288fcc4304424ab8f56388f72652d8fafc65a4b9020896f2cde297080f2a540e7b7ce5af0b3446e1258d1dd7f245cf54124b4c6e17da21b90a0ebd22605e6f45c9f136d7a13eaac1c0f7487de8bd6d924972408ebb58af71e76fd7b012a8d0e165f3ae2e5077a8648e619", 16), //PRIVATE EXPONENT D
                      new BigInteger("EA5A71FCE5047001BA6882A899632A2703EDB2A5EB6A5CBD3F6D59D4068F03186162C3C20AD926EA9B7CAB0A9F3424255A2F54BEFF922B5A7DF4D9E92A4315258000000000000000", 16),	//PRIME_P, SETP (DGI-8205)
                      new BigInteger("C92B822028008D31D4626370F52AC671728C717132224D02F1F4BAD1280DC60745D5CE3D6CB86DBF4335425282D7A5384BAE26D8CD7361A066E1C20D2A05DEF38000000000000000", 16),	//PRIME_Q, SETQ (DGI-8204)
                      new BigInteger("9C3C4BFDEE02F5567C45AC7066421C1A029E7719479C3DD37F9E3BE2AF0A021040EC82815C90C49C67A8720714CD6D6E3C1F8DD4AA61723C53F891461C2CB8C38000000000000000", 16),	//PRIME_EXPONENT_P, SETDP1 (DGI-8203)
                      new BigInteger("861D016AC555B3768D96ECF5F8C72EF64C5DA0F6216C33574BF87C8B70092EAF83E3DED39DD0492A2CCE2C3701E518D0327419E5DE4CEBC04496815E1C03E9F78000000000000000", 16),	//PRIME_EXPONENT_Q, SETDQ1 (DGI-8202)
                      new BigInteger("588C13E98E5294BE0161E432F8B0E77A208D8AAC95A7D8091099AFEC687A72A59C0CB179A327DFB044F0BFAA21D6232E0C29C99BBAD8A735B3952007F49DF43C8000000000000000", 16));	//CRT_COEFFICIENT, SETPQ  (DGI-8201)
				*/

                    len = (short) 0;        //skip parseDOL
                    break;

                case (short) 0x3001: //Application Internal Data
                    //contains
                    //1. Card Additional Processes, primitive tag '9F68' - 4 bytes
                    //(byte)0x9F, (byte)0x68, (byte)0x04, (byte)0x10,(byte)0x00, (byte)0x90, (byte)0x00,
                    //byte 1 = 0x10 = 000 0000
                    //		 = bit 5 (Streamlined qVSDC supported)
                    //
                    //byte 3 = 0x90 = 1001 0000
                    //		 = bit 8 (online PIN supported for domestic transaction)
                    //		 = bit 5 (signature supported)

                    break;

                case (short) 0x9206: // MSD response data
                    CURRENT_PROFILE = PROFILE_MSD;
                    break;

                case (short) 0x9115: // qVSDC online response data without ODA
                    //80 E2 00 01 68 91 15 65 82 02 00 40 94 04 08 03 03 00 57 13 40 05 57 10 00 00 19 89 D1 51 02 21 55 55 53 33 00 34 1F 5F 34 01 99 9F 10 1F 43 01 00 20 00 00 00 00 01 02 03 04 04 30 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 9F 26 08 FE 2C ED AC 8C FD CB C8 9F 27 01 80 9F 36 02 00 00 9F 6C 02 00 00 9F 6E 04 23 8C 00 00
                    //
                    //      CVN(1) DKI(1)     CVR(6) 	DigitalWalletID(4) DerivationData(4) IDDformat(1) IDD(14)
                    // 	  43     01      D32000000000 	01020304	   04 30 00 01	     00		  00 00 00 00 00 00 00 00 00 00 00 00 00 00
                    // 9F101F 43 01 D32000000000 01020304 04300001 00 0000000000000000000000000000
                    //
                    // Store Data DGI 9115
                    // 80 E2 00 01 68
                    //	9115 65 						DGI 9115
                    //	82   02   0040						AIP
                    //	94   04   08030300 					AFL
                    //	57   13   4005571000001989D12102215555533300341F 	T2ED
                    //	5F34 01   00 						PAN
                    //	9F10 1F   						IAD
                    //		  43 							CVN
                    //		  01 							DKI
                    //		  002000000000 						CVR
                    //		  01020304 						DIGITAL WALLET ID
                    //                 04300001 						DERIVATION DATA
                    //		  00							IDD FORMAT
                    //                 00 00 00 00 00 00 00 00 00 00 00 00 00 00 		IDD
                    //	9F26 08   Fe 2C ED AC 8C FD CB C8			APPLICATION CRYPTOGRAM
                    //	9F27 01   80 						CID
                    //	9F36 02   0000 						ATC
                    //	9F6C 02   0000 						CTQ
                    //	9F6E 04   238C0000  					FFI

                    CURRENT_PROFILE = PROFILE_QVSDC_ONLINE_WO_ODA;
                    break;

                case (short) 0x9117: // qVSDC online response data with ODA
                    CURRENT_PROFILE = PROFILE_QVSDC_ONLINE_WITH_ODA;
                    break;

                default:
                    break;
            }

            offset = dgiDataOffset;
            len += dgiDataOffset;

            while (offset < len) {
                span = Util.parseDOL(inBuffer, offset, myTL);
                storeTagValue(myTL[Util.TAG], inBuffer, (short) (offset + span), myTL[Util.LEN]);
                offset += (short) (span + myTL[Util.LEN]);
            }
        }

        return storeData_responseApdu;
    }


    /**
     * Helper function to insert the Account Parameters Index  and decimalized Cryptogram in Read Record.
     *
     * @param record
     */
    private static void modifyRecord(byte[] record) {

        //YHHHHCC=4300001

        //* Store Data DGI 0101
        //80 E2 00 01 1A 0101 17 7015 5713 4005571000001989D15102215555533300341F
        //                                 4005571000001989D12102215555533300341F
        //4005571000001989 	acct#
        //D					field separator
        //1510				Expire date
        //221				service code
        //55 55 53 3		Acct parameter index	YHHHHCC
        //30 03 41			decimalized cryptogram
        //F					padding

        //* Read Record SFI 1 Record 1
        //T - 00 B2 01 0C 00
        //C - 70 15 57 13 40 05 57 10 00 00 19 89 D1 51 02 21
        //     43 00 00 15 77 20 0F 90 00
        //
        //4005571000001989
        //D
        //1510
        //221
        //4300001
        //577200
        //F

        short T2InsertOffset = MS_RecordsOffsetInfo;    //24
        //byte[] AP_AccountParametersIndex2 = AccountParameters.getAccountParametersIndex();
        byte[] AP_AccountParametersIndex = Tag_ACCOUNT_PARAMETERS_INDEX;

        // Insert Account Parameters Index
        // 70 15 57 13 40 05 57 10 00 00 19 89 D1 51 02 21 55 55 53 33 00 34 1F
        // 0  1  2  3  4  5  6  7  8  9  10 11 12 13 14 15 16 17 18 19 20 21 22
        short off = (short) ((decimalizedCrypto_Data[DCRYPTO_TRACK2_OFF] * 2) + T2InsertOffset); //(4*2) + 24 = 32
        short byte_off = (short) (off / 2);    //16

        // Need to overlay with Account Parameters Index (7 nibbles)
        if (((off % 2) == 1)) {
            record[byte_off] = (byte) ((record[byte_off] & 0xF0) + AP_AccountParametersIndex[(short) 0]);
            byte_off++;
            record[byte_off] = (byte) ((AP_AccountParametersIndex[(short) 1] << 4) + AP_AccountParametersIndex[(short) 2]);
            byte_off++;
            record[byte_off] = (byte) ((AP_AccountParametersIndex[(short) 3] << 4) + AP_AccountParametersIndex[(short) 4]);
            byte_off++;
            record[byte_off] = (byte) ((AP_AccountParametersIndex[(short) 5] << 4) + AP_AccountParametersIndex[(short) 6]);
            byte_off++;

            // Move the offset to Decimalized Cryptogram
            record[byte_off++] = (byte) ((decimalizedCryptogram[(short) 0] << 4) + decimalizedCryptogram[(short) 1]);
            record[byte_off++] = (byte) ((decimalizedCryptogram[(short) 2] << 4) + decimalizedCryptogram[(short) 3]);
            record[byte_off++] = (byte) ((decimalizedCryptogram[(short) 4] << 4) + decimalizedCryptogram[(short) 5]);
        } else {
            record[byte_off++] = (byte) ((AP_AccountParametersIndex[(short) 0] << 4) + AP_AccountParametersIndex[(short) 1]);
            record[byte_off++] = (byte) ((AP_AccountParametersIndex[(short) 2] << 4) + AP_AccountParametersIndex[(short) 3]);
            record[byte_off++] = (byte) ((AP_AccountParametersIndex[(short) 4] << 4) + AP_AccountParametersIndex[(short) 5]);
            record[byte_off] = (byte) ((AP_AccountParametersIndex[(short) 6] << 4) + (record[byte_off] & 0x0F));

            // Move the offset to Decimalized Cryptogram
            record[byte_off] = (byte) ((record[byte_off] & 0xF0) + decimalizedCryptogram[(short) 0]);
            byte_off++;
            record[byte_off] = (byte) ((decimalizedCryptogram[(short) 1] << 4) + decimalizedCryptogram[(short) 2]);
            byte_off++;
            record[byte_off] = (byte) ((decimalizedCryptogram[(short) 3] << 4) + decimalizedCryptogram[(short) 4]);
            byte_off++;
            record[byte_off] = (byte) ((decimalizedCryptogram[(short) 5] << 4) + (record[byte_off] & 0x0F));
        }
    }


    /**************************
     * SELECT PPSE Processing
     **************************/
    /**
     * This is main handler for SELECT PPSE RESPONSE processing.
     *
     * @param commandApdu
     * @return
     */
    protected static int selectPPSE(byte[] commandApdu, byte[] outBuffer) {
        int returnVal = 0;

        if (commandApdu[OFFSET_P1] != (byte) 0x04) {
            //returnVal =  INDEX_SW_VIS_SELECTED_FILE_INVALIDATED;	//0x6283 =  -14
            returnVal = INDEX_SW_HCE_INVALID_SELECT;                //0x6A88 =  -15
            return returnVal;
        }

        // We only allow P2 values of '00' or '02'
        if ((commandApdu[OFFSET_P2] != (byte) 0x00) && (commandApdu[OFFSET_P2] != (byte) 0x02)) {
            //returnVal =  INDEX_SW_VIS_SELECTED_FILE_INVALIDATED;	//0x6283 =  -14
            returnVal = INDEX_SW_HCE_INVALID_SELECT;                //0x6A88 =  -15
            return returnVal;
        }

        //VCPCS B.5
        //DGI 9102
        //Second check of setting default value
        if (FirstTime_setDefaultValues == OURFALSE)
            setDefaultValues();

        //todo
        //totalVisaAID = getPPSE_DirectoryEntry((byte[])commandApdu, (short)18, (short)commandApdu.length);

        //if (totalVisaAID == (short)1)
        //{

        if (SELECT_PPSE_APDU_RESP_DGI9102 != null) {
            Util.arrayCopy(SELECT_PPSE_APDU_RESP_DGI9102, (short) 0, outBuffer, (short) 0, (short) SELECT_PPSE_APDU_RESP_DGI9102.length);
            Util.arrayCopy(ISO7816_SW_NO_ERROR, (short) 0, outBuffer, (short) (SELECT_PPSE_APDU_RESP_DGI9102.length - 2), (short) ISO7816_SW_NO_ERROR.length);
            returnVal = SELECT_PPSE_APDU_RESP_DGI9102.length;
        } else {
            returnVal = INDEX_ISO7816_SW_CONDITIONS_NOT_SATISFIED;    //6985 = -3

        }

        //}
        //else
        //{
        //select PPSE contains zero or greater than 1 AIDs then return with empty PPSE
        //	Util.arrayCopy(ISO7816_SW_NO_ERROR, (short)0, SELECT_PPSE_APDU_RESP_DGI9102_EMPTY_PPSE, (short)(SELECT_PPSE_APDU_RESP_DGI9102_EMPTY_PPSE.length-2), (short)ISO7816_SW_NO_ERROR.length);
        //    return SELECT_PPSE_APDU_RESP_DGI9102_EMPTY_PPSE;
        //}
        return returnVal;
    }


    /**************************
     * SELECT PAYWAVE Processing
     **************************/
    /**
     * This is main handler for SELECT AID (PAYWAVE) RESPONSE processing.
     *
     * @param commandApdu
     * @return
     */
    protected static int selectPAYWAVE(byte[] commandApdu, byte[] outBuffer) {
        //VCPCS B.4
        //DGI 9103
        int returnVal = 0;

        if (commandApdu[OFFSET_P1] != (byte) 0x04) {
            //returnVal =  INDEX_SW_VIS_SELECTED_FILE_INVALIDATED;	//0x6283 =  -14
            returnVal = INDEX_SW_HCE_INVALID_SELECT;                //0x6A88 =  -15
            return returnVal;
        }

        // We only allow P2 values of '00' or '02'
        if ((commandApdu[OFFSET_P2] != (byte) 0x00) && (commandApdu[OFFSET_P2] != (byte) 0x02)) {
            //returnVal =  INDEX_SW_VIS_SELECTED_FILE_INVALIDATED;	//0x6283 =  -14
            returnVal = INDEX_SW_HCE_INVALID_SELECT;                //0x6A88 =  -15
            return returnVal;
        }


        if ((short) commandApdu[OFFSET_LC] != (short) 7)    //not equal 7 bytes AID
        {
            //returnVal =  INDEX_SW_VIS_SELECTED_FILE_INVALIDATED;	//0x6283 =  -14
            returnVal = INDEX_SW_HCE_INVALID_SELECT;                //0x6A88 =  -15
            return returnVal;
        }


        if (Util.arrayCompare(AccountConfigurationParameters.getPAYWAVEAID(), (short) 2, commandApdu, OFFSET_CDATA, (short) commandApdu[OFFSET_LC]))    //accept partial AID
        {
            //short offset = 0;
            //short responseApduLength = 6;		// 6F ln ... A5 ln... 9000

            if (SELECT_PAYWAVE_APDU_RESP_DGI9103 != null) {
                Util.arrayCopy(SELECT_PAYWAVE_APDU_RESP_DGI9103, (short) 0, outBuffer, (short) 0, (short) SELECT_PAYWAVE_APDU_RESP_DGI9103.length);
                Util.arrayCopy(ISO7816_SW_NO_ERROR, (short) 0, outBuffer, (short) (SELECT_PAYWAVE_APDU_RESP_DGI9103.length - 2), (short) ISO7816_SW_NO_ERROR.length);
                returnVal = SELECT_PAYWAVE_APDU_RESP_DGI9103.length;
            } else {
                returnVal = INDEX_ISO7816_SW_CONDITIONS_NOT_SATISFIED;    //6985 = -3

          		/*
	        	responseApduLength = (short)(responseApduLength +
	        									Tag_PAYWAVE_DF.length +
	        									Tag_AppLabel.length +
	        									Tag_PDOL.length);

	            if ((short)(responseApduLength-4) > 127)
	            	SELECT_PAYWAVE_APDU_RESP = new byte[responseApduLength+1];
	        	else
	        		SELECT_PAYWAVE_APDU_RESP = new byte[responseApduLength];

	        	SELECT_PAYWAVE_APDU_RESP[offset++] = FCI_TEMPLATE;
	        	SELECT_PAYWAVE_APDU_RESP[offset++] = (byte)(responseApduLength-4);

	            if ((short)(responseApduLength-4) > 127)
	        	{
	            	SELECT_PAYWAVE_APDU_RESP[offset-1] = (byte)0x81;
	            	SELECT_PAYWAVE_APDU_RESP[offset++] = (byte)(responseApduLength-4);
	        	}

	        	Util.arrayCopy(Tag_PAYWAVE_DF, (short)0, SELECT_PAYWAVE_APDU_RESP, offset, (short)Tag_PAYWAVE_DF.length);
	        	offset = (short)(offset + Tag_PAYWAVE_DF.length);

	        	SELECT_PAYWAVE_APDU_RESP[offset++] = FCI_PPROPRIETARY_TEMPLATE;
	        	SELECT_PAYWAVE_APDU_RESP[offset++] = (byte)(Tag_AppLabel.length + Tag_PDOL.length);

	        	Util.arrayCopy(Tag_AppLabel, (short)0, SELECT_PAYWAVE_APDU_RESP, offset, (short)Tag_AppLabel.length);
	        	offset = (short)(offset + Tag_AppLabel.length);

	        	Util.arrayCopy(Tag_PDOL, (short)0, SELECT_PAYWAVE_APDU_RESP, offset, (short)Tag_PDOL.length);
	        	offset = (short)(offset + Tag_PDOL.length);

	        	Util.arrayCopy(ISO7816_SW_NO_ERROR, (short)0, SELECT_PAYWAVE_APDU_RESP, offset, (short)ISO7816_SW_NO_ERROR.length);

	    		responseApdu = SELECT_PAYWAVE_APDU_RESP;
	    		*/
            }
        } else {
            //returnVal =  INDEX_SW_VIS_SELECTED_FILE_INVALIDATED;	//0x6283 =  -14
            returnVal = INDEX_SW_HCE_INVALID_SELECT;                //0x6A88 =  -15
        }

        return returnVal;
    }


    /**************************
     * GPO Processing
     **************************/
    /**
     * This is a helper function to check TTQ to determine MSD/qVSDC support.
     *
     * @param commandApdu
     * @return
     */
    private static byte checkTTQ(byte[] commandApdu) {
        byte retCode = OURTRUE;
        byte ttqByte1 = commandApdu[TTQ_INDEX];


        // Check TTQ and decide which response to send back
        if ((ttqByte1 & TTQ_B1b6_CONTACTLESS_QVSDC_SUPPORTED) != 0)    //1011 0000 & 1010 0000 = 1010 0000
        {

            if ((ttqByte1 & TTQ_B1b1_ODA_FOR_ONLINE_AUTH_SUPPORTED) != 0) {
                supportODA = OURTRUE;
                CURRENT_PROFILE = PROFILE_QVSDC_ONLINE_WITH_ODA;    //QVSDC_DETECTED;
            } else {
                supportODA = OURFALSE;
                CURRENT_PROFILE = PROFILE_QVSDC_ONLINE_WO_ODA;        //QVSDC_DETECTED;
            }
        } else if ((ttqByte1 & TTQ_B1b8_CONTACTLESS_MSD_SUPPORTED) != 0)    //1011 0000 & 1010 0000 = 1010 0000
        {
            CURRENT_PROFILE = PROFILE_MSD;                        //MSD_DETECTED;
        } else
            retCode = OURFALSE;

        return retCode;

    }

    /**
     * This is helper function to calculate qVSDC cryptogram using CVN 43 (same as CVN10, but using LUK)
     *
     * @return
     */
    private static byte[] generateCryptogram(byte[] commandApdu) {

        //todo check for cvn17 or cvn43 , Tag_QVSDC_CVN
        //cvn17 algorithm using amount, unpredictable number, atc and cvr then triple DES
        if (Tag_QVSDC_CVN[0] == (byte) 0x11)    //cvn17
        {
            //hendy todo
            //generateCryptogram_CVN17(commandApdu);
            tmpCryptoDataBuffer = new byte[65]; //9 blocks of 8 bytes
            short bufferOffset = 0;
            Util.arrayCopy(commandApdu, GPO_Data_Offsets_CL[GPO_DO_AMOUNT], tmpCryptoDataBuffer, bufferOffset, (short) 6);
            bufferOffset += 6;
            Util.arrayCopy(commandApdu, GPO_Data_Offsets_CL[GPO_DO_UNP_NBR], tmpCryptoDataBuffer, bufferOffset, (short) 4);
            bufferOffset += 4;
            Util.setShort(tmpCryptoDataBuffer, bufferOffset, (short) ATC);
            bufferOffset += 2;
            Util.arrayCopy(Tag_QVSDC_CVR, CVR_BYTE_2, tmpCryptoDataBuffer, bufferOffset, (short) 1);
            bufferOffset += 1;
        } else {
            //VCPCS 8.4
            //PDOL + AIP(2) + ATC(2) + CVR(4)
            tmpCryptoDataBuffer = new byte[65]; //9 blocks of 8 bytes
            short bufferOffset = 0;

            Util.arrayCopy(commandApdu, GPO_Data_Offsets_CL[GPO_DO_AMOUNT], tmpCryptoDataBuffer, bufferOffset, (short) 6);
            bufferOffset += 6;
            Util.arrayCopy(commandApdu, GPO_Data_Offsets_CL[GPO_DO_AMT_OTHER], tmpCryptoDataBuffer, bufferOffset, (short) 6);
            bufferOffset += 6;
            Util.arrayCopy(commandApdu, GPO_Data_Offsets_CL[GPO_DO_TERM_CC], tmpCryptoDataBuffer, bufferOffset, (short) 2);
            bufferOffset += 2;
            Util.arrayCopy(commandApdu, GPO_Data_Offsets_CL[GPO_DO_TVR], tmpCryptoDataBuffer, bufferOffset, (short) 5);
            bufferOffset += 5;
            Util.arrayCopy(commandApdu, GPO_Data_Offsets_CL[GPO_DO_TRAN_CC], tmpCryptoDataBuffer, bufferOffset, (short) 2);
            bufferOffset += 2;
            Util.arrayCopy(commandApdu, GPO_Data_Offsets_CL[GPO_DO_TRAN_DATE], tmpCryptoDataBuffer, bufferOffset, (short) 3);
            bufferOffset += 3;
            Util.arrayCopy(commandApdu, GPO_Data_Offsets_CL[GPO_DO_TRAN_TYPE], tmpCryptoDataBuffer, bufferOffset, (short) 1);
            bufferOffset += 1;
            Util.arrayCopy(commandApdu, GPO_Data_Offsets_CL[GPO_DO_UNP_NBR], tmpCryptoDataBuffer, bufferOffset, (short) 4);
            bufferOffset += 4;

            // At the end of the Data, copy AIP (2 bytes), ATC (2 bytes), and CVR (4 bytes) in that order
            Util.setShort(tmpCryptoDataBuffer, bufferOffset, AIP[(short) CURRENT_PROFILE]);
            bufferOffset += 2;
            Util.setShort(tmpCryptoDataBuffer, bufferOffset, (short) ATC);
            bufferOffset += 2;
            //Util.arrayCopy(Tag_QVSDC_CVR, (short)0, tmpCryptoDataBuffer, bufferOffset, (short)4);bufferOffset +=4;
            Util.arrayCopy(Tag_QVSDC_IAD, (short) 0, tmpCryptoDataBuffer, bufferOffset, (short) Tag_QVSDC_IAD.length);
            bufferOffset += Tag_QVSDC_IAD.length;    //32


            //byte[] tmpCryptoDataBuffer3 = new byte[] {
            //		 (byte)0x00,  (byte)0x00,  (byte)0x00,  (byte)0x00,  (byte)0x56,  (byte)0x12,  (byte)0x00,  (byte)0x00,
            //		 (byte)0x00,  (byte)0x00,  (byte)0x00,  (byte)0x00,  (byte)0x08,  (byte)0x40,  (byte)0x00,  (byte)0x00,
            //		 (byte)0x00,  (byte)0x00,  (byte)0x00,  (byte)0x08,  (byte)0x40,  (byte)0x09,  (byte)0x11,  (byte)0x30,
            // 		 (byte)0x00,  (byte)0x12,  (byte)0x34,  (byte)0x56,  (byte)0x78,  (byte)0x00,  (byte)0x40,  (byte)0x00,
            // 		 (byte)0x01,  (byte)0x6D,  (byte)0xA0,  (byte)0x00,  (byte)0x00,  (byte)0x00,  (byte)0x00,  (byte)0x00
            //};
            //
            //byte[] textEncrypted3 = encryption_ISO9797_1_MAC_works(tmpCryptoDataBuffer3, CRYPTO_IV);
	/*
			00 00 00 00 56 12 00 00
			00 00 00 00 08 40 00 00
			00 00 00 08 40 09 11 30
			00 12 34 56 78 00 40 00
			01 6D A0 00 00
	*/
			/*
		    byte[] tmpCryptoDataBuffer2 = new byte[] {
		    		 (byte)0x00,  (byte)0x00,  (byte)0x00,  (byte)0x00,  (byte)0x16,  (byte)0x18,  (byte)0x00,  (byte)0x00,
		     		 (byte)0x00,  (byte)0x00,  (byte)0x00,  (byte)0x00,  (byte)0x08,  (byte)0x40,  (byte)0x00,  (byte)0x00,
		     		 (byte)0x00,  (byte)0x00,  (byte)0x00,  (byte)0x08,  (byte)0x40,  (byte)0x09,  (byte)0x11,  (byte)0x30,
		     		 (byte)0x00,  (byte)0x12,  (byte)0x34,  (byte)0x56,  (byte)0x78,  (byte)0x00,  (byte)0x40,  (byte)0x00,
		     		 (byte)0x01,  (byte)0x43,  (byte)0x01,  (byte)0x00,  (byte)0x20,  (byte)0x00,  (byte)0x00,  (byte)0x00,
		     		 (byte)0x00,  (byte)0x01,  (byte)0x02,  (byte)0x03,  (byte)0x04,  (byte)0x04,  (byte)0x30,  (byte)0x00,
		     		 (byte)0x01,  (byte)0x00,  (byte)0x00,  (byte)0x00,  (byte)0x00,  (byte)0x00,  (byte)0x00,  (byte)0x00,
		     		 (byte)0x00,  (byte)0x00,  (byte)0x00,  (byte)0x00,  (byte)0x00,  (byte)0x00,  (byte)0x00,  (byte)0x00,
		    };
	*/

			/*
			00 00 00 00 16 18 00 00
			00 00 00 00 08 40 00 00
			00 00 00 08 40 09 11 30
			00 12 34 56 78 00 40 00
			01 43 01 00 20 00 00 00
			00 01 02 03 04 04 30 00
			01 00 00 00 00 00 00 00
			00 00 00 00 00 00 00 00
	*/
			/*
			 00 00 00 00 10 00 00 00
			 00 00 00 00 08 40 00 00
			 00 00 00 08 40 00 01 25
			 00 12 34 56 78 00 40 00
			 01 43 01 00 20 00 00 00
			 00 01 02 03 04 04 30 00
			 01 00 00 00 00 00 00 00
			 00 00 00 00 00 00 00 00
			 */
			/*
		    byte[] tmpCryptoDataBuffer2 = new byte[] {
		    		 (byte)0x00,  (byte)0x00,  (byte)0x00,  (byte)0x00,  (byte)0x10,  (byte)0x00,  (byte)0x00,  (byte)0x00,
		     		 (byte)0x00,  (byte)0x00,  (byte)0x00,  (byte)0x00,  (byte)0x08,  (byte)0x40,  (byte)0x00,  (byte)0x00,
		     		 (byte)0x00,  (byte)0x00,  (byte)0x00,  (byte)0x08,  (byte)0x40,  (byte)0x00,  (byte)0x01,  (byte)0x25,
		     		 (byte)0x00,  (byte)0x12,  (byte)0x34,  (byte)0x56,  (byte)0x78,  (byte)0x00,  (byte)0x40,  (byte)0x00,
		     		 (byte)0x01,  (byte)0x43,  (byte)0x01,  (byte)0x00,  (byte)0x20,  (byte)0x00,  (byte)0x00,  (byte)0x00,
		     		 (byte)0x00,  (byte)0x01,  (byte)0x02,  (byte)0x03,  (byte)0x04,  (byte)0x04,  (byte)0x30,  (byte)0x00,
		     		 (byte)0x01,  (byte)0x00,  (byte)0x00,  (byte)0x00,  (byte)0x00,  (byte)0x00,  (byte)0x00,  (byte)0x00,
		     		 (byte)0x00,  (byte)0x00,  (byte)0x00,  (byte)0x00,  (byte)0x00,  (byte)0x00,  (byte)0x00,  (byte)0x00,
		    };
			*/
        }

        byte[] textEncrypted = encryption_ISO9797_1_MAC(tmpCryptoDataBuffer);
        return textEncrypted;
    }


    private static int Track2EquivalentDProcessing(byte[] inBuffer, short inOffset, short inLength) {
        //VCPCS 9.3
        int returnVal = 0;
        short ACCOUNT_PARAMETERS_INDEX_offset = (short) 12;

        if (AccountConfigurationParameters.getMSDSupport() == (byte) 0) {
            //qVSDC only, MSD not supported
            //VCPCS Table 8
            //Do nothing with Track 2 Equivalent Data, contains only static value


            //40 05 57 10 00 00 19 89 	acct# (8 bytes = 16digits)
            //D					field separator
            //1210				Expire date
            //221				service code
            //0123				PIN Verification Field(5)
            //123 9999			Discretionary Data
            //					dCVV = 123 or CVV only
            //					ATC = 9999
            //F					padding

        } else {
            //If both qVSDC and MSD supported
            //VCPCS Table 7
            //SE used dCVV, HCE used decimalized cryptogram
            //update Account Parameter Index (YHHHHCC)
            //update Decimalized Cryptogram

            decimalizedCryptogramProcessing();

            // offset Account Parameters Index
            short byte_off = ACCOUNT_PARAMETERS_INDEX_offset;    //12

            // Need to overlay with Account Parameters Index
            if (((byte_off % 2) == 1))    //reminder
            {

                //insert Account Parameters Index (7 nibbles)
                Tag_QVSDC_T2ED[byte_off] = (byte) ((Tag_QVSDC_T2ED[byte_off] & 0xF0) + Tag_ACCOUNT_PARAMETERS_INDEX[(short) 0]);
                byte_off++;
                Tag_QVSDC_T2ED[byte_off] = (byte) ((Tag_ACCOUNT_PARAMETERS_INDEX[(short) 1] << 4) + Tag_ACCOUNT_PARAMETERS_INDEX[(short) 2]);
                byte_off++;
                Tag_QVSDC_T2ED[byte_off] = (byte) ((Tag_ACCOUNT_PARAMETERS_INDEX[(short) 3] << 4) + Tag_ACCOUNT_PARAMETERS_INDEX[(short) 4]);
                byte_off++;
                Tag_QVSDC_T2ED[byte_off] = (byte) ((Tag_ACCOUNT_PARAMETERS_INDEX[(short) 5] << 4) + Tag_ACCOUNT_PARAMETERS_INDEX[(short) 6]);
                byte_off++;

                //insert Decimalized Cryptogram
                Tag_QVSDC_T2ED[byte_off++] = (byte) ((decimalizedCryptogram[(short) 0] << 4) + decimalizedCryptogram[(short) 1]);
                Tag_QVSDC_T2ED[byte_off++] = (byte) ((decimalizedCryptogram[(short) 2] << 4) + decimalizedCryptogram[(short) 3]);
                Tag_QVSDC_T2ED[byte_off++] = (byte) ((decimalizedCryptogram[(short) 4] << 4) + decimalizedCryptogram[(short) 5]);

            } else {

                //insert Account Parameters Index (7 nibbles)
                Tag_QVSDC_T2ED[byte_off++] = (byte) ((Tag_ACCOUNT_PARAMETERS_INDEX[(short) 0] << 4) + Tag_ACCOUNT_PARAMETERS_INDEX[(short) 1]);
                Tag_QVSDC_T2ED[byte_off++] = (byte) ((Tag_ACCOUNT_PARAMETERS_INDEX[(short) 2] << 4) + Tag_ACCOUNT_PARAMETERS_INDEX[(short) 3]);
                Tag_QVSDC_T2ED[byte_off++] = (byte) ((Tag_ACCOUNT_PARAMETERS_INDEX[(short) 4] << 4) + Tag_ACCOUNT_PARAMETERS_INDEX[(short) 5]);
                Tag_QVSDC_T2ED[byte_off] = (byte) ((Tag_ACCOUNT_PARAMETERS_INDEX[(short) 6] << 4) + (Tag_QVSDC_T2ED[byte_off] & 0x0F));

                //insert Decimalized Cryptogram
                Tag_QVSDC_T2ED[byte_off] = (byte) ((Tag_QVSDC_T2ED[byte_off] & 0xF0) + decimalizedCryptogram[(short) 0]);
                byte_off++;
                Tag_QVSDC_T2ED[byte_off] = (byte) ((decimalizedCryptogram[(short) 1] << 4) + decimalizedCryptogram[(short) 2]);
                byte_off++;
                Tag_QVSDC_T2ED[byte_off] = (byte) ((decimalizedCryptogram[(short) 3] << 4) + decimalizedCryptogram[(short) 4]);
                byte_off++;
                Tag_QVSDC_T2ED[byte_off] = (byte) ((decimalizedCryptogram[(short) 5] << 4) + (Tag_QVSDC_T2ED[byte_off] & 0x0F));

                //0  1  2  3  4  5  6  7  8  9  10 11 12 13 14 15 16 17 18
                //40 05 57 10 00 00 19 89 D1 21 02 21 55 55 53 33 00 34 1F
                //
                //40 05 57 10 00 00 19 89 	acct# (8 bytes = 16digits)
                //D					field separator
                //1210				Expire date
                //221				service code
                //55 55 53  3		Account parameter index (7 digits)	YHHHHCC
                //30 03 41			decimalized cryptogram (6 digits)
                //F					padding

                //overwrite with new data
                //43 00 00 1		Account parameter index (7 digits)
                //57 72 00			decimalized cryptogram (6 digits)

            }
        }

        return returnVal;
    }


    private static int insertIAD(short inLength, byte[] outBuffer) {
        //VCPCS 9.1
        int returnVal = 0;
        short offset = 0;

        //	9F10  20							IAD
        //		  1F   							IAD LENGTH
        //		  43 							CVN
        //		  01 							DKI
        //		  002000000000 					CVR
        //		  01020304 						DIGITAL WALLET ID
        //        04300001 						DERIVATION DATA
        //		  00							IDD FORMAT
        //        00 00 00 00 00 00 00 00 00 00 00 00 00 00 	IDD PADDING

        //IAD = 9F10 20 1F  43 01 002000000000 01020304 04300001 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

        outBuffer[Util.setShort(outBuffer, (short) offset, (short) 0x9F10)] = (byte) inLength;
        offset += 3;
        Util.arrayCopy(Tag_QVSDC_IAD_LEN, (short) 0, outBuffer, offset, (short) 1);
        offset++;        //IAD length
        Util.arrayCopy(Tag_QVSDC_CVN, (short) 0, outBuffer, offset, (short) 1);
        offset++;            //CVN
        Util.arrayCopy(Tag_QVSDC_DKI, (short) 0, outBuffer, offset, (short) 1);
        offset++;        //DKI
        Util.arrayCopy(Tag_QVSDC_CVR, (short) 0, outBuffer, offset, (short) 6);
        offset += 6;        //CVR
        Util.arrayCopy(Tag_QVSDC_DWPI, (short) 0, outBuffer, offset, (short) 4);
        offset += 4;        //DWPI
        Util.arrayCopy(Tag_QVSDC_DDLUK, (short) 0, outBuffer, offset, (short) 4);
        offset += 4;        //DDLUK
        Util.arrayCopy(Tag_QVSDC_IDD_FORMAT, (short) 0, outBuffer, offset, (short) 1);
        offset++;    //IDD Format
        Util.arrayCopy(Tag_QVSDC_IDD_PADDING, (short) 0, outBuffer, offset, (short) 14);            //IDD padding

        return returnVal;
    }


    /**
     *
     */
    private static void decimalizedCryptogramSetup() {
        byte[] rec = getRecord(decimalizedCrypto_Data[DCRYPTO_TRACK2_SFI], decimalizedCrypto_Data[DCRYPTO_TRACK2_REC]);
        if (rec != null) {
            if (t2edWorkdspace == null)
                t2edWorkdspace = new byte[16];
            else
                Arrays.fill(t2edWorkdspace, (byte) 0);

            short off = 0, span;
            short len = (short) rec.length;

            while (off < len) {
                span = Util.parseDOL(rec, off, myTL);

                if (myTL[Util.TAG] == (short) 0x0070) {
                    off += span;
                } else if (myTL[Util.TAG] == (short) 0x0057) {
                    decimalizedCrypto_Data[DCRYPTO_TRACK2_OFF] = (byte) (off + 2);
                    break;
                } else {
                    off += (short) (span + myTL[Util.LEN]);
                }
            }

            off = decimalizedCrypto_Data[DCRYPTO_TRACK2_OFF];    //16

            short positionOfFS = Util.findFS(rec, off);

            // If we enforce a max of 17 digits for the PAN, then 18 is used in this test.
            // If we allow an 18 or 19 digit PAN, then we use 19 or 20 for this test.
            // if ((positionOfFS < 4) || (positionOfFS > 20))
            //      ISOException.throwIt(ISO7816.SW_WRONG_DATA);

            Util.nibbleCopy(rec, (short) ((off * 2) + 4), t2edWorkdspace, (short) 4, (short) (positionOfFS - 4));
            Util.nibbleCopy(rec, (short) ((off * 2) + positionOfFS + 1), t2edWorkdspace, positionOfFS, (short) 7);


            //0  1  2  3  4  5  6  7  8  9  10 11 12 13 14 15 16 17 18
            //40 05 57 10 00 00 19 89 D1 21 02 21 55 55 53 33 00 34 1F
            //
            //40 05 57 10 00 00 19 89 	acct# (8 bytes = 16digits)
            //D							field separator
            //1210						Expire date
            //221						service code
            //55 55 53  3				Account parameter index (7 digits)	YHHHHCC
            //30 03 41					decimalized cryptogram (6 digits)
            //F							padding


            //70 15 57 13 40 05 57 10 00 00 19 89 D1 51 02 21 55 55 53 33 00 34 1F
            //0  1  2  3  4  5  6   7  8  9 10 11 12 13 14 15 16 = positionOfFS
            //MS_RecordsOffsetInfo = 24
            MS_RecordsOffsetInfo = (short) (positionOfFS + 8); // retrieve Account Parameters Index offset based on Field Separator Offset
        }
    }

    private static void locateSDADrecord() {
        // Read Record SFI 2 Record 4
        //T - 00 B2 04 14 00
        //C - 70 0D 9F 69 07 01 00 00 00 00 00 00 9F 4B 60

        short lenOfAFL;
        short index;
        short offset;
        short numOfQuads;
        short span;
        byte localSFI, localRecNo, firstRec, lastRec;
        byte[] AFLptr;
        byte[] rec;

        //SDADsfi = (byte)1;
        //SDADrec = (byte)4;
        //SDADoffset = (short)13;

        locateSDADoffset = OURTRUE;
        if (AFL != null) {
            for (short i = 0; i < AFL.length; i++) {
                AFLptr = (byte[]) AFL[i];
                if ((AFLptr == null) || (AFLptr.length == 0))
                    continue;

                numOfQuads = (short) (AFLptr.length / 4);
                for (short j = (short) 0; (j < numOfQuads); j++) {
                    index = (short) (j * 4);
                    localSFI = (byte) (Util.getUByte(AFLptr, index) >> 3);
                    firstRec = AFLptr[(short) (index + 1)];
                    lastRec = AFLptr[(short) (index + 2)];

                    for (localRecNo = firstRec; (localRecNo <= lastRec); localRecNo++) {
                        short entry = findRecord(localSFI, localRecNo);
                        rec = getRecord(localSFI, localRecNo);
                        if (rec != null) {
                            offset = (short) 0;
                            while (offset < rec.length) {
                                span = Util.parseDOL(rec, offset, myTL);
                                if (myTL[Util.TAG] == (short) 0x0070) {
                                    offset += span;
                                    continue;
                                } else if (myTL[Util.TAG] == (short) 0x9F47)  //found 9F47 PUBLIC EXPONENT E
                                {
                                    //tag9F47_publicExponentE = rec[(short)(offset + span)];

                                    tag9F47_publicExponentE = Util.byteHexString((byte) rec[(short) (offset + span)]);

                                    //myTL[Util.LEN]
                                    //rec[(short)(offset + span)]
                                    //tag9F47_publicExponentE  = "3";	//todo hendy
                                } else if (myTL[Util.TAG] == (short) 0x9F4B)  //found 9F4B SDAD
                                {
                                    SDADsfi = (byte) localSFI;
                                    SDADrec = (byte) localRecNo;
                                    SDADoffset = (short) (offset + span);
                                    SDADlength = (short) myTL[Util.LEN];
                                } else if (myTL[Util.TAG] == (short) 0x9F69)  //found 9F69 Card Authentication related data
                                {
                                    CardAuthenRelatedDataoffset = (short) (offset + span);
                                }
                                offset += (short) (span + myTL[Util.LEN]);
                            }
                        }
                    }
                }
            }
        }

    }

    private static byte[] encryption_ISO9797_1_MAC(byte[] source) {
        //VCPCS 8.4 qVSDC Cryptogram
        //CVN10 + UDK = CVN43 + LUK
        //CVN10 = PDOL + AIP(2) + ATC(2) + CVR(4) + padding zeroes

        //ISO/IEC 9797-1 MAC algorithm 3 with block cipher DES, zero IV (8 bytes)
        //Retail MACing algorithm.
        //VIS Book #2
        //	Section D.3.2 (page D-7)
        //	Step #3, Step #4
        //	Figure D-1 (page D-8)

        byte[] mac = new byte[(short) 8];
        byte[] keyLeft = new byte[(short) 8];
        byte[] keyRight = new byte[(short) 8];
        //initialization vector (IV) = always 8 bytes of zeroes

        try {
            Util.arrayCopy(Tag_ACCOUNT_PARAMETERS_LUK, (short) 0, keyLeft, (short) 0, (short) 8);
            Util.arrayCopy(Tag_ACCOUNT_PARAMETERS_LUK, (short) 8, keyRight, (short) 0, (short) 8);


            int datasize = source.length + 1;
            if ((datasize % 8) != 0)
                datasize += 8 - (datasize % 8);
            byte[] newdata = new byte[datasize];
            System.arraycopy(source, 0, newdata, 0, source.length);

            SecretKey KA = new SecretKeySpec(keyLeft, "DES");
            SecretKey KB = new SecretKeySpec(keyRight, "DES");
            Cipher CipherK = Cipher.getInstance("DES/ECB/NoPadding");

            // Encrypt block by block with Key-A
            byte[] inputData = new byte[8];
            byte[] outputData = new byte[8];
            byte[] dataBlock = new byte[8];


            CipherK.init(Cipher.ENCRYPT_MODE, KA);
            outputData = CipherK.doFinal(newdata, (short) 0, (short) 8);

            int blocks = newdata.length / 8;
            for (int i = 1; i < (blocks); i++) {
                System.arraycopy(newdata, (i * 8), dataBlock, 0, 8);
                inputData = Util.XOR(outputData, dataBlock);

                CipherK.init(Cipher.ENCRYPT_MODE, KA);
                outputData = CipherK.doFinal(inputData);
            }

            // Decrypt the resulting block with Key-B
            CipherK.init(Cipher.DECRYPT_MODE, KB);
            inputData = CipherK.doFinal(outputData);

            // Encrypt the resulting block with Key-A
            CipherK.init(Cipher.ENCRYPT_MODE, KA);
            mac = CipherK.doFinal(inputData);

        } catch (NoSuchAlgorithmException e) {
        } catch (NoSuchPaddingException e) {
        } catch (InvalidKeyException e) {
        } catch (IllegalBlockSizeException e) {
        } catch (BadPaddingException e) {
        }

        return mac;
    }


    /**
     * Encrypt method using TDES.
     *
     * @param source
     * @param IV
     * @return
     */
    private static byte[] encryption_TripleDES(byte[] source, byte[] IV) {
        //VCPCS Figure 1
        //VCPCS 8.3
        //for MSD:
        //	source = CRYPTO_MSD	'00 00 00 01'
        //	IV = CRYPTO_IV      '00 00 00 00'     	//initialization vector (IV)

        //Triple DES Encryption (also known as DES-EDE, 3DES, or Triple-DES).
        //Data is encrypted using the DES algorithm three separate times.
        //It is first encrypted using the first subkey, then decrypted with the second subkey,
        //and encrypted with the third subkey.

        Cipher cipher = null;
        byte[] cipherText = null;
        //SecretKey keyLUK = new SecretKeySpec(AccountParameters.getLUK(), "DESede");
        SecretKey keyLUK = new SecretKeySpec(Tag_ACCOUNT_PARAMETERS_LUK, "DESede");
        IvParameterSpec iv = new IvParameterSpec(IV);

        try {
            cipher = Cipher.getInstance("DESede/CBC/NoPadding");        //1
            cipher.init(Cipher.ENCRYPT_MODE, keyLUK, iv);                //2
            cipherText = cipher.doFinal(source);                        //3

        } catch (NoSuchAlgorithmException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (BadPaddingException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        ;

        return cipherText;
    }


    /**
     * This is the helper function to calculate MSD decimalized cryptogram.
     *
     * @param commandApdu
     * @return
     */
    private static byte[] decimalizedCryptogramProcessing() {
        //VCPCS 8.3
    	/*
    	  The limited use cryptogram is created by first encrypting the fixed value ' '
    	  with the Limited Use Key using Triple DES and an Initial Chaining Vector of binary zeroes.

    	 	Block 1 = Beginning with the leftmost digit, extract all numeric digits '0' through '9'.
			Block 2 = Beginning with the leftmost digit, extract all hexadecimal digits 'A' through 'F'
			          and convert each into a numeric digit by subtracting 10 from each digit.
			Block 3 = Concatenate Block 1 and Block 2.
			The decimalized cryptogram is the 6 leftmost (most significant) bytes of Block 3.

			input: t2edWorkdspace[16], decimalizedCryptogram[6]
    	 */

        tmpDataBuffer = new byte[TMPDATABUFFER_Length];

        // Copy the Template to the WorkSpace
        Util.arrayCopy(t2edWorkdspace, (short) 0, tmpDataBuffer, (short) 16, (short) 16);

        byte[] cipherText = encryption_TripleDES(CRYPTO_MSD, CRYPTO_IV);

        Util.arrayCopy(cipherText, (short) 0, tmpDataBuffer, (short) 16, (short) 8);

        // Search through Block 1 for digits (first pass, 0..9; second pass, A..F)
        //  Stop when I've found 6 digits for the decCrypto
        byte byt;
        byte nib;
        for (short i = 0, j = 0; i < 16; i++) {
            if (i < 8) {
                byt = tmpDataBuffer[(short) (16 + i)];
                nib = (byte) ((byt >> 4) & 0x0F);
                if (nib <= 9) {
                    decimalizedCryptogram[j++] = nib;
                    if (j > 5)
                        break;
                }
                nib = (byte) (byt & 0x0F);
                if (nib <= 9) {
                    decimalizedCryptogram[j++] = nib;
                    if (j > 5)
                        break;
                }
            } else {
                byt = tmpDataBuffer[(short) (8 + i)]; //(16 + i - 8)
                nib = (byte) ((byt >> 4) & 0x0F);
                if (nib >= 10) {
                    decimalizedCryptogram[j++] = (byte) (nib - 10);
                    if (j > 5)
                        break;
                }
                nib = (byte) (byt & 0x0F);
                if (nib >= 10) {
                    decimalizedCryptogram[j++] = (byte) (nib - 10);
                    if (j > 5)
                        break;
                }
            }
        }

        return null;
    }


    /**
     * Construct the GPO Response.
     * If qVSDC, use Format 2.
     * If MSD, use Format 1.
     *
     * @param currentProfile
     * @return
     */
    private static byte[] constructGPOResponse(byte[] commandApdu, short currentProfile) {
        //todo byte array return with int return
        short bufferOffset = (short) 0;
        byte[] localAFL = ((byte[]) (AFL[currentProfile]));
        byte[] inBuffer = null;
        byte[] outBuffer = null;
        byte[] responseApdu = new byte[(short) MAXAPDU_SIZE];

        inBuffer = new byte[(short) MAXAPDU_SIZE];
        outBuffer = new byte[(short) MAXAPDU_SIZE];

        if (currentProfile == PROFILE_MSD) {
            //VCPCS 7.5.2
            //MSD, Format 1 = '80'

            // '82' | '02' | AIP
            bufferOffset = Util.setShort(inBuffer, bufferOffset, AIP[currentProfile]);                    //00 0C

            // '94' | AFL.length | AFL
            if (AFL[currentProfile] != null && ((short) localAFL.length != 0)) {
                Util.arrayCopy(localAFL, (short) 0, inBuffer, bufferOffset, (short) localAFL.length);        //00 0C 08 01 01 00
                bufferOffset += (short) localAFL.length;
            }


        } else    //if (currentProfile == PROFILE_QVSDC_ONLINE_WO_ODA) or  (currentProfile == PROFILE_QVSDC_ONLINE_WITH_ODA)
        {
            //VCPCS 7.5.1.2
            //QVSDC, Format 2 = '77'

            //setting CTQ and CVR
            CVMProcessing((byte[]) commandApdu);

            //AIP = 82 02 0040 (TLV)
            bufferOffset = Util.setShort(inBuffer, Util.setShort(inBuffer, bufferOffset, (short) 0x8202), AIP[currentProfile]);

            //AFL = 94 04 08030300
            if (AFL[currentProfile] != null && ((short) localAFL.length != 0)) {
                inBuffer[bufferOffset++] = (byte) 0x94;
                inBuffer[bufferOffset++] = (byte) localAFL.length;
                Util.arrayCopy(localAFL, (short) 0, inBuffer, bufferOffset, (short) localAFL.length);
                bufferOffset += (short) localAFL.length;
            }


            //T2ED = 57   13   4005571000001989D12102215555533300341F
            if (Tag_QVSDC_T2ED != null) {
                Track2EquivalentDProcessing(Tag_QVSDC_T2ED, (short) 0, (short) Tag_QVSDC_T2ED.length);

                inBuffer[bufferOffset++] = (byte) 0x57;
                inBuffer[bufferOffset++] = (byte) Tag_QVSDC_T2ED.length;
                Util.arrayCopy(Tag_QVSDC_T2ED, (short) 0, inBuffer, bufferOffset, (short) Tag_QVSDC_T2ED.length);
                bufferOffset += (short) Tag_QVSDC_T2ED.length;
            }

            //PAN = 5F34 01   00
            if (currentProfile == PROFILE_QVSDC_ONLINE_WO_ODA) {
                if (Tag_QVSDC_PSN != null) {
                    inBuffer[Util.setShort(inBuffer, bufferOffset, (short) 0x5F34)] = (byte) Tag_QVSDC_PSN.length;
                    bufferOffset += 3;
                    Util.arrayCopy(Tag_QVSDC_PSN, (short) 0, inBuffer, bufferOffset, (short) Tag_QVSDC_PSN.length);
                    bufferOffset += (short) Tag_QVSDC_PSN.length;
                }
            }

            //IAD = 9F10 1F  43 01 002000000000 01020304 04300001 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
            if (Tag_QVSDC_IAD != null) {
                insertIAD((short) Tag_QVSDC_IAD.length, outBuffer);

                Util.arrayCopy(outBuffer, (short) 0, inBuffer, bufferOffset, (short) (Tag_QVSDC_IAD.length + 3));
                bufferOffset += (short) (Tag_QVSDC_IAD.length + 3);
            }

            // Application Cryptogram = 9F26 08   Fe 2C ED AC 8C FD CB C8
            if (Tag_QVSDC_AC != null) {
                inBuffer[Util.setShort(inBuffer, bufferOffset, (short) 0x9F26)] = (byte) Tag_QVSDC_AC.length;
                bufferOffset += 3;

                Util.arrayCopy(generateCryptogram(commandApdu), (short) 0, inBuffer, bufferOffset, (short) Tag_QVSDC_AC.length);
                bufferOffset += (short) Tag_QVSDC_AC.length;
            }

            // CID = 9F27 01   80
            if (Tag_QVSDC_CID != null) {
                inBuffer[Util.setShort(inBuffer, bufferOffset, (short) 0x9F27)] = (byte) Tag_QVSDC_CID.length;
                bufferOffset += 3;
                Util.arrayCopy(Tag_QVSDC_CID, (short) 0, inBuffer, bufferOffset, (short) Tag_QVSDC_CID.length);
                bufferOffset += (short) Tag_QVSDC_CID.length;
            }

            // ATC = 9F36 02   0000
            inBuffer[Util.setShort(inBuffer, bufferOffset, (short) 0x9F36)] = (byte) 0x02;
            bufferOffset = Util.setShort(inBuffer, (short) (bufferOffset + 3), (short) ATC);


            // CTQ = 9F6C 02   0000
            if (Tag_QVSDC_CTQ != null) {
                inBuffer[Util.setShort(inBuffer, bufferOffset, (short) 0x9F6C)] = (byte) Tag_QVSDC_CTQ.length;
                bufferOffset += 3;
                Util.arrayCopy(Tag_QVSDC_CTQ, (short) 0, inBuffer, bufferOffset, (short) Tag_QVSDC_CTQ.length);
                bufferOffset += (short) Tag_QVSDC_CTQ.length;
            }

            // FFI = 9F6E 04   238C0000
            if (currentProfile == PROFILE_QVSDC_ONLINE_WO_ODA) {
                if (Tag_QVSDC_FFI != null) {
                    inBuffer[Util.setShort(inBuffer, bufferOffset, (short) 0x9F6E)] = (byte) Tag_QVSDC_FFI.length;
                    bufferOffset += 3;
                    Util.arrayCopy(Tag_QVSDC_FFI, (short) 0, inBuffer, bufferOffset, (short) Tag_QVSDC_FFI.length);
                    bufferOffset += (short) Tag_QVSDC_FFI.length;
                }
            }

        }

        //ODA=Offline data authentication is a cryptographic check to validate the card using public-key cryptography.
        //perso spec page 120 note #6
        //qVSDC online with ODA, DGI-9117, TTQ b1b1=1 (supportODA), CAP b2b6=1
        if ((supportODA == OURTRUE) &&
                ((Tag_CAP != null) && ((Tag_CAP[CAP_BYTE_2] & CAP_B2b6_DISABLE_ODA_AUTHORIZATIONS) != 0))
                ) {
            ;//todo	ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);	//6985
        }

        if (((AIP[currentProfile] & AIP_DDA_SUPP) != 0) &&
                ((Tag_CAP != null) && ((Tag_CAP[CAP_BYTE_2] & CAP_B2b6_DISABLE_ODA_AUTHORIZATIONS) == 0)) &&
                (supportODA == OURTRUE)
                )

        {
            if (locateSDADoffset == OURFALSE) {
                locateSDADrecord();    //todo hendy only called one
            }
            // Store the SDAD in a temporary location
            // in case it should be returned in a record
            //todo sdadLen = generateSDAD(inBuffer, cryptogramStatus);
            generateSDAD((byte[]) commandApdu);

        }

        /*
 		//Util.arrayCopy(commandApdu, GPO_Data_Offsets_CL[GPO_DO_AMOUNT], gpoCTTA, (short)0, (short)6);
        if (Util.addBCD(CTTA, gpoCTTA, newCTTA) == OVERFLOW)
        	//error

        else
        	Util.arrayCopy(newCTTA, (short)0, CTTA, (short)0, BCDLEN);
        */

        outBuffer = new byte[(short) (bufferOffset)];
        Util.arrayCopy(inBuffer, (short) 0, outBuffer, (short) 0, (short) outBuffer.length);
        return outBuffer;
    }


    /**
     * Returns qVSDC GPO Response
     *
     * @return
     */
    protected static byte[] qVSDCProcessing(byte[] commandApdu, short currentProfile) {
        //todo byte arrayreturn to int return
        short bufferOffset = (short) 0;
        byte[] respData = constructGPOResponse((byte[]) commandApdu, currentProfile);


        QVSDC_GPO_RESPONSE = new byte[(short) (respData.length + 4)];    //'77' format 2 + length + SW 9000
        QVSDC_GPO_RESPONSE[bufferOffset++] = RESP_MSG_TEMPLATE_FORMAT_2;
        QVSDC_GPO_RESPONSE[bufferOffset++] = (byte) (respData.length);
        Util.arrayCopy(respData, (short) 0, QVSDC_GPO_RESPONSE, bufferOffset, (short) respData.length);
        bufferOffset += (short) respData.length;
        Util.setShort(QVSDC_GPO_RESPONSE, bufferOffset, (short) 0x9000);    //SW1 SW2

        return QVSDC_GPO_RESPONSE;
    }


    /**
     * Returns MSD GPO Response based on Table 2
     * - Response Message Template Format 1
     * - Application Interchange Profile (AIP)
     * - Application File Locator (AFL)
     *
     * @return
     */
    protected static byte[] msdProcessing(byte[] commandApdu) {
        //todo byte arrayreturn to int return
        short bufferOffset = (short) 0;
        byte[] respData = constructGPOResponse((byte[]) commandApdu, PROFILE_MSD);    //AIP+AFL=00 0C 08 01 01 00

        MSD_GPO_RESPONSE = new byte[(short) (respData.length + 4)];
        MSD_GPO_RESPONSE[bufferOffset++] = RESP_MSG_TEMPLATE_FORMAT_1;    //80
        MSD_GPO_RESPONSE[bufferOffset++] = (byte) (respData.length);        //80 xx
        Util.arrayCopy(respData, (short) 0, MSD_GPO_RESPONSE, bufferOffset, (short) respData.length);    //80 xx =00 0C 08 01 01 00
        bufferOffset += (short) respData.length;
        Util.setShort(MSD_GPO_RESPONSE, bufferOffset, (short) 0x9000);    //SW1 SW2 //80 xx =00 0C 08 01 01 00 90 00

        return MSD_GPO_RESPONSE;
    }


    /**
     * This is main handler for GPO RESPONSE processing.
     *
     * @param commandApdu
     * @return
     */

    protected static int getProcessingOptions(byte[] commandApdu, byte[] outBuffer) {
        byte[] responseApdu = new byte[(short) 2];
        short codeCounter = 0;    //implement security measure
        int returnVal = 0;
        supportODA = OURFALSE; // terminal supports ODA

        if (commandApdu[OFFSET_P1] != (byte) 0x00)
            return INDEX_ISO7816_SW_FUNC_NOT_SUPPORTED; // 0x6A81 = -7

        if (commandApdu[OFFSET_P2] != (byte) 0x00)
            return INDEX_ISO7816_SW_FUNC_NOT_SUPPORTED; // 0x6A81 = -7

        //APDU command data offset : CDATA = 5
        //tag '83' PDOL tag, Length, PDOL data
        //EMV book #3, 6.5.8.3
        if (commandApdu[OFFSET_CDATA] != (byte) 0x83)
            return INDEX_ISO7816_SW_FUNC_NOT_SUPPORTED; // 0x6A81 = -7
        else
            codeCounter++;  //1
        //0  1  2  3  4  5  6
        short cmdLength = commandApdu[(short) (OFFSET_CDATA + 1)];    //80 A8 00 00 23 83 21

        // case No PDOL
        if (cmdLength == (short) 0)
            return INDEX_ISO7816_SW_FUNC_NOT_SUPPORTED; // 0x6A81 = -7

        // case gpo command length <> pdol length
        if (cmdLength != (short) ((commandApdu[OFFSET_LC] & 0xFF) - 2))
            return INDEX_ISO7816_SW_FUNC_NOT_SUPPORTED; // 0x6A81 = -7

        //VCPCS 7.10
        //case GPO PDOL length <> PDOL length from Select PAYWAVE
        if (cmdLength != PDOL_RelatedDataLength_CL)
            return INDEX_ISO7816_SW_FUNC_NOT_SUPPORTED; // 0x6A81 = -7
        else
            codeCounter++;  //2


        if (codeCounter == 2) {
            // Req 7.13/7.14, Based on TTQ, return qVSDC or MSD response
            if (checkTTQ(commandApdu) != OURTRUE)
                return INDEX_ISO7816_SW_CONDITIONS_NOT_SATISFIED; //6985 = -3
            else
                codeCounter++;  //3
        }

        if (codeCounter == 3) {
            // Req 7.12, ATC Update
            if (incrementATC() != OURTRUE) {
                NextGenHostApduService.APDUstate = STATE_BLOCKED;    //blocked app
                return INDEX_ISO7816_SW_CONDITIONS_NOT_SATISFIED; //6985 = -3
            } else
                codeCounter++;  //4


            if (codeCounter == 4) {
                switch (CURRENT_PROFILE) {
                    case PROFILE_QVSDC_ONLINE_WO_ODA:
                    case PROFILE_QVSDC_ONLINE_WITH_ODA:
                        responseApdu = qVSDCProcessing(commandApdu, CURRENT_PROFILE);
                        Util.arrayCopy(responseApdu, (short) 0, outBuffer, (short) 0, (short) responseApdu.length);
                        returnVal = responseApdu.length;
                        break;

                    case PROFILE_MSD:
                        responseApdu = msdProcessing(commandApdu);
                        Util.arrayCopy(responseApdu, (short) 0, outBuffer, (short) 0, (short) responseApdu.length);
                        returnVal = responseApdu.length;
                        break;

                    default:
                        return INDEX_ISO7816_SW_WRONG_DATA; // 0x6A80 = -6

                }
            }
        }


        return returnVal;
    }


    /**************************
     * Read Record Processing
     **************************/
    /**
     * This is main handler for READ RECORD RESPONSE processing.
     *
     * @param commandApdu
     * @return
     */
    protected static int readRecord(byte[] commandApdu, byte[] outBuffer) {
        //VCPCS B.2
        //VCPCS table 1 and table 2
        int returnVal = 0;
        byte[] responseApdu = null;
        byte[] Record = null;

        byte p1 = commandApdu[OFFSET_P1];        // p1 = Record Number
        byte p2 = commandApdu[OFFSET_P2];        // p2 = SFI (bit4-8)
        byte sfi = (byte) ((p2 >> 3) & 0x1F);    // SFI = shift 3 to the right, AND , 0001 1111
        short record0204offset;


        Record = getRecord(sfi, p1);
        if (Record != null) {
            responseApdu = new byte[(short) (Record.length + 2)];
            Util.arrayCopy(Record, (short) 0, responseApdu, (short) 0, (short) Record.length);
            responseApdu[Record.length] = (byte) 0x90;
            responseApdu[(short) (Record.length + 1)] = (byte) 0x00;

            if (CURRENT_PROFILE == PROFILE_MSD) {
                if ((MS_RecordsOffsetInfo != (short) -1)
                        &&
                        (decimalizedCrypto_Data != null)
                        &&
                        (sfi == decimalizedCrypto_Data[DCRYPTO_TRACK2_SFI])
                        &&
                        (p1 == decimalizedCrypto_Data[DCRYPTO_TRACK2_REC])) {
                    decimalizedCryptogramProcessing();
                    modifyRecord(responseApdu);
                }
            } else if (CURRENT_PROFILE == PROFILE_QVSDC_ONLINE_WITH_ODA) {
                // Read Record SFI 2 Record 4
                //T - 00 B2 04 14 00
                //C - 70 6A 9F 69 05 01 00 00 00 00 9F 4B 60

                if (locateSDADoffset == OURFALSE) {
                    locateSDADrecord();    //todo hendy only called one
                } else {
                    if ((sfi == SDADsfi) && (p1 == SDADrec)) {
                        record0204offset = CardAuthenRelatedDataoffset;
                        responseApdu[record0204offset++] = (byte) 0x01;    //fDDA version number
                        Util.arrayCopy(cardUnpredNumber, (short) 0, responseApdu, (short) record0204offset, (short) 4);
                        record0204offset += 4;
                        Util.arrayCopy(Tag_QVSDC_CTQ, (short) 0, responseApdu, (short) record0204offset, (short) 2);
                        record0204offset += 2;

                        //append SDADrecord with tag 9F4B SDAD data
                        //nIC(96)
                        byte[] SDADrecord = new byte[(short) (responseApdu.length + SDADlength)];
                        Util.arrayCopy(responseApdu, (short) 0, SDADrecord, (short) 0, (short) responseApdu.length);
                        Util.arrayCopy(tmpSDADBuffer, (short) 0, SDADrecord, (short) SDADoffset, (short) tmpSDADBuffer.length);
                        SDADrecord[(short) (SDADrecord.length - 2)] = (byte) 0x90;
                        SDADrecord[(short) (short) (SDADrecord.length - 1)] = (byte) 0x00;

                        Util.arrayCopy(SDADrecord, (short) 0, outBuffer, (short) 0, (short) SDADrecord.length);
                        returnVal = SDADrecord.length;
                        return returnVal;
                    }
                }
            }


            Util.arrayCopy(responseApdu, (short) 0, outBuffer, (short) 0, (short) responseApdu.length);
            returnVal = responseApdu.length;
        } else {
            returnVal = INDEX_ISO7816_SW_RECORD_NOT_FOUND;    //0x6A83 = -8
        }

        return returnVal;
    }

    /**
     * Deposits the tag name into data buffer and return the value of tag.
     *
     * @param commandApdu
     * @return
     */
    protected static int getTagValue(short tag, byte[] outBuffer) {
        //byte[] inBuffer = null;
        byte[] responseApdu = new byte[(short) 2];
        short TagLen = (short) 0;


        Util.arrayCopy(ISO7816_SW_NO_ERROR, (short) 0, responseApdu, (short) 0, (short) ISO7816_SW_NO_ERROR.length);
        //commndApdu->  [ 1] 80 ca 9f 36 00
        //outBuffer     [ 5] 9f 36 02 00 11 90 00

        //DebugActivity.sendLog("VCBPAProcess: getTagValue", Util.byteArrayToHex(commandApdu));

        //inBuffer = new byte[(short)MAXAPDU_SIZE];
        switch (tag) {
            case (short) 0x9F7D:  // Application Code Level
                if (TAG_ACL != null) {
                    Util.setShort(outBuffer, (short) 0, (short) tag);                                    //tag
                    Util.arrayCopy(TAG_ACL, (short) 0, outBuffer, (short) 3, (short) TAG_ACL.length);    //value
                    TagLen = (short) TAG_ACL.length;                                                    //length
                }
                break;

            case (short) 0x9F36:  // ATC
                Util.setShort(outBuffer, (short) 0, (short) tag);                                        //tag
                Util.setShort(outBuffer, (short) 3, (short) ATC);                                        //value
                TagLen = (short) 2;                                                                    //length
                break;

            case (short) 0x9F6C:  // Card Transaction Qualifiers
                if (Tag_QVSDC_CTQ != null) {
                    Util.setShort(outBuffer, (short) 0, (short) tag);                                                //tag
                    Util.arrayCopy(Tag_QVSDC_CTQ, (short) 0, outBuffer, (short) 3, (short) Tag_QVSDC_CTQ.length);    //value
                    TagLen = (short) Tag_QVSDC_CTQ.length;                                                        //length
                }
                break;

            case (short) 0x9F6E:  // Form Factor Indicator
                if (Tag_QVSDC_FFI != null) {
                    Util.setShort(outBuffer, (short) 0, (short) tag);                                                //tag
                    Util.arrayCopy(Tag_QVSDC_FFI, (short) 0, outBuffer, (short) 3, (short) Tag_QVSDC_FFI.length);    //value
                    TagLen = (short) Tag_QVSDC_FFI.length;                                                        //length
                }
                break;

            case (short) 0x9F68:  // Card Additional Processes (qVSDC)
                if (Tag_CAP != null) {
                    Util.setShort(outBuffer, (short) 0, (short) tag);                                                //tag
                    Util.arrayCopy(Tag_CAP, (short) 0, outBuffer, (short) 3, (short) Tag_CAP.length);                //value
                    TagLen = (short) Tag_CAP.length;                                                                //length
                }
                break;

            default:
                //Util.arrayCopy(ISO7816_SW_WRONG_DATA, (short)0, responseApdu, (short)0, (short)ISO7816_SW_WRONG_DATA.length);
                return INDEX_ISO7816_SW_WRONG_DATA;        //INDEX_ISO7816_SW_WRONG_DATA = -6
        }

        outBuffer[2] = (byte) TagLen;    //tag len
        //outBuffer      9f 36 02 00 11 90 00
        return (TagLen + 3);
    }


    /**
     * @return
     */
    private static byte incrementATC() {
        //todo MAX_ATC = 0x7FFF (32767) or 0xFFFF (65535)

        // Increment ATC and keep below MAX
        // If MAX is reached, Permanently Block the APP.
        if (ATC < MAX_ATC) {
            ATC++;
            if ((ATC >= MAX_ATC) || (ATC <= 0x00)) {
                return OURFALSE;
            }
            return OURTRUE;
        }

        return OURFALSE;
    }

    protected static short getPPSE_DirectoryEntry(byte[] PPSE_FCItemplate, short offset, short len) {
        //find offset for PDOL tags
        byte[] responseApdu = ISO7816_SW_NO_ERROR;
        short span;
        short totalVISAAID = 0;

        //Visa AID
        //An AID using the Visa Registered Application Provider Identifier (RID, 'A0 00 00 00 03')
        //		that has a Proprietary Application Identifier Extension (PIX) assigned by Visa International.
        //Visa PIXs:
        //	'1010' � Visa Debit and Visa Credit
        //	'2010' � Visa Electron
        //	'3010' � Interlink
        //	'8010' � PLUS
        //Regional AIDs using the reserved range of Visa assigned PIXs are permitted.

        if (FCI_PropData_Reg == null)
            FCI_PropData_Reg = new Object[VISAAID_SIZE];    //4

        while (offset < len) {
            span = Util.parseDOL((byte[]) PPSE_FCItemplate, offset, myTL);

            if ((myTL[Util.TAG] == (short) 0x00A5) || (myTL[Util.TAG] == (short) 0xBF0C) || (myTL[Util.TAG] == (short) 0x84)) {
                offset += span;
                continue;
            } else if (myTL[Util.TAG] == (short) 0x61)  //directory entry
            {
                short offset_ADFNAMElen = (short) PPSE_FCItemplate[(short) (offset + 3)];
                short offset_ADFNAMEdata = (short) (offset + 4);

                if (FCI_PropData_Reg[totalVISAAID] == null)
                    FCI_PropData_Reg[totalVISAAID] = new byte[offset_ADFNAMElen];

                Util.arrayCopy(PPSE_FCItemplate, offset_ADFNAMEdata, ((byte[]) FCI_PropData_Reg[totalVISAAID]), (short) 0, offset_ADFNAMElen);
                totalVISAAID++;
            }
            offset += (short) (span + myTL[Util.LEN]);
        }
        return totalVISAAID;
    }


    protected static int getGPO_PDOLdataOffsets(byte[] PAYWAVE_FCItemplate, short offset, short len) {
        //find offset for PDOL tags
        int returnVal = 0;
        short span;

        while (offset < len) {
            span = Util.parseDOL((byte[]) PAYWAVE_FCItemplate, offset, myTL);

            if ((myTL[Util.TAG] == (short) 0x00A5) || (myTL[Util.TAG] == (short) 0xBF0C)) {
                offset += span;
                continue;
            } else if (myTL[Util.TAG] == (short) 0x9F38)  // I found the PDOL
            {
                // For GPO cmd, this would be 7, the byte following the '83 len'.  For GenAC it would be 5.
                PDOL_RelatedDataLength_CL = Util.setDataOffsetsFromDOL((byte[]) PAYWAVE_FCItemplate, (short) (offset + span),
                        myTL[Util.LEN],
                        PDOL_Tags,
                        GPO_Data_Offsets_CL,
                        (short) 7);

            }
            offset += (short) (span + myTL[Util.LEN]);
        }
        return returnVal;
    }


    protected static byte CVMProcessing(byte[] commandApdu) {
        //VCPCS 7.5.1.1 qVSDC CVM processing
        //VCPS H.1 Streamlined qVSDC
        byte retCode = OURTRUE;
        byte local_ttqByte1 = commandApdu[(short) GPO_Data_Offsets_CL[GPO_DO_TTQ]];
        byte local_ttqByte2 = commandApdu[(short) (GPO_Data_Offsets_CL[GPO_DO_TTQ] + 1)];
        byte local_ttqByte3 = commandApdu[(short) (GPO_Data_Offsets_CL[GPO_DO_TTQ] + 2)];

        if (Tag_QVSDC_CTQ != null) {
            //set CTQ byte1 bit8-7=00
            Tag_QVSDC_CTQ[CTQ_BYTE_1] &= CTQ_CLEAR_2MSBITS; //0011 1111

            //set CTQ byte2 bit8=0
            Tag_QVSDC_CTQ[CTQ_BYTE_2] &= CTQ_CLEAR_1MSBITS; //0111 1111

            //set CVR byte1=00000000
            Tag_QVSDC_CVR[CVR_BYTE_1] = (byte) 0x00;

            // VCPS 2.1 Req H.6, CVM Required Check
            if ((local_ttqByte2 & TTQ_B2b7_CVM_REQUIRED) != 0) {
                if (Tag_CAP != null)    //tag '9F68, Card Additional Processes
                {
                    // VCPS 2.1 Req H.7, Determine Common CVM
                    if (
                            ((local_ttqByte1 & TTQ_B1b3_ONLINE_PIN_SUPPORTED) != 0)
                                    &&
                                    (
                                            ((Tag_CAP[CAP_BYTE_3] & CAP_B3b8_ONLINE_PIN_SUPPORTED_FOR_DOMESITC_TXN) != 0)
                                                    ||
                                                    ((Tag_CAP[CAP_BYTE_3] & CAP_B3b7_ONLINE_PIN_SUPPORTED_FOR_INTL_TXN) != 0)
                                    )
                            ) {
                        //online PIN
                        Tag_QVSDC_CTQ[CTQ_BYTE_1] |= CTQ_B1b8_ONLINE_PIN_REQUIRED;
                        Tag_QVSDC_CVR[CVR_BYTE_1] |= CVR_B1b85_0110_TERMINAL;
                        Tag_QVSDC_CVR[CVR_BYTE_1] |= CVR_B1b41_1110_ONLINE_PIN;
                    } else if (
                            ((local_ttqByte3 & TTQ_B3b7_MOBILE_FUNC_SUPPORTED_CONSUMER_DEVICE_CVM) != 0)
                                    &&
                                    ((Tag_CAP[CAP_BYTE_3] & CAP_B3b4_CONSUMER_DEVICE_CVM_SUPPORTED) != 0)
                            ) {
                        //Consumer Device CVM
                        Tag_QVSDC_CTQ[CTQ_BYTE_2] |= CTQ_B2b8_CONSUMER_DEVICE_CVM_PERFORMED;

                        //CVM Verifying Entity
                        //table 6
                        Tag_QVSDC_CVR[CVR_BYTE_1] |= CVR_B1b85_0000_NO_CD_CVM;
                        Tag_QVSDC_CVR[CVR_BYTE_1] |= CVR_B1b85_0101_MOBILE_APP;


                        //CVM Verified Type
                        //table 6
                        Tag_QVSDC_CVR[CVR_BYTE_1] |= CVR_B1b41_0000_NO_CD_CVM;
                    } else if (
                            ((local_ttqByte1 & TTQ_B1b2_SIGNATURE_SUPPORTED) != 0)
                                    &&
                                    ((Tag_CAP[CAP_BYTE_3] & CAP_B3b5_SIGNATURE_SUPPORTED) != 0)
                            ) {
                        //Signature Option
                        Tag_QVSDC_CTQ[CTQ_BYTE_1] |= CTQ_B1b7_SIGNATURE_REQUIRED;
                        Tag_QVSDC_CVR[CVR_BYTE_1] |= CVR_B1b85_0110_TERMINAL;
                        Tag_QVSDC_CVR[CVR_BYTE_1] |= CVR_B1b41_1101_SIGNATURE;
                    } else {
                        //((local_ttqByte2  & TTQ_B2b7_CVM_REQUIRED) == 0)
                        //no Common CVM

                        //Consumer Device CVM
                        Tag_QVSDC_CTQ[CTQ_BYTE_2] |= CTQ_B2b8_CONSUMER_DEVICE_CVM_PERFORMED;

                        //CVM Verifying Entity
                        //table 6
                        Tag_QVSDC_CVR[CVR_BYTE_1] = (byte) 0x00;
                    }
                }
            } else {
                //((local_ttqByte2  & TTQ_B2b7_CVM_REQUIRED) == 0)
                //no Common CVM

                //Consumer Device CVM
                Tag_QVSDC_CTQ[CTQ_BYTE_2] |= CTQ_B2b8_CONSUMER_DEVICE_CVM_PERFORMED;

                //CVM Verifying Entity
                //table 6
                Tag_QVSDC_CVR[CVR_BYTE_1] = (byte) 0x00;
            }

            //ARQC return
            //Tag_QVSDC_CVR[CVR_BYTE_2] |= (CVR_B2b87_10_NO2 | CVR_B2b65_10_ARQC1); // 1000 0000 |  0010 0000 = 0xA0
            Tag_QVSDC_CVR[CVR_BYTE_2] |= CVR_B2b65_10_ARQC1; //0010 0000 = 0x20
        }

        return retCode;
    }

    protected static byte generateSDAD(byte[] commandApdu) {
        byte returnVal = OURFALSE;
        short hashOffset;

        Cipher cipherRSA = null;
        byte[] key = null;
        Signature signatureRSA = null;

        MessageDigest MessageDigestRSA = null;
		 /*
			 java.security.spec.RSAPrivateCrtKeySpec.RSAPrivateCrtKeySpec
			 (BigInteger modulus, BigInteger publicExponent, BigInteger privateExponent, BigInteger primeP, BigInteger primeQ, BigInteger primeExponentP, BigInteger primeExponentQ, BigInteger crtCoefficient)

			 Creates a new RSAMultiPrimePrivateCrtKeySpec with the specified modulus, public exponent, private exponent,
			 prime factors, prime exponents, crt coefficient, and additional primes.

				 Parameters:
			 modulus the modulus n.
			 publicExponent the public exponent e.
			 privateExponent the private exponent d.
			 primeP the prime factor p of n.				dgi-8205
			 primeQ the prime factor q of n.				dgi-8204
			 primeExponentP the exponent of the prime p.	dgi-820
			 primeExponentQ the exponent of the prime q.
			 crtCoefficient the CRT coefficient q^-1 mod p.
		 */


        //768

        //tag9F47_publicExponentE  = "3";	//todo hendy
        //baseConversion_radix 	 = 16;
		 /*
		 String dgi8103_modulusN 		 = "C7F317AFC57A6975E28F5631CBAB89B0AEA779D2FBFF9B6B0A54AE88CFDC7BD72C128291C9AFFF38663F856BCA8B18BB492465D2354A00B9228FADCCDDE8279391B8A8DF0F28E38122CE1C4120495775FFCFABD93172BAA5EB09E44B5D59334F";
		 String tag9F47_publicExponentE  = "3";
		 String dgi8101_privateExponentD = "854CBA752E519BA3EC5F8ECBDD1D0675C9C4FBE1FD5512475C38745B353DA7E4C80C570BDBCAAA25997FAE47DC5CBB26585031F72C65B00FB1EA26E4A904710A4CAF2CADC41865EC0790A76154B95A4EF99138EFEEB6B2AE2584A2D080CEC3EB";
		 String dgi8205_prime1P			 = "E8BC63E5479455E26577F715D587FE68870CD2C8BCE8595529E3F628DA86B9511067221020CCAA30111D18CC4CDDF55F";
		 String dgi8204_prime2Q 		 = "DBEFB6FA2B1D22BF32387C600AD97F9B97A51311AC1BF149ED912B0646AC96AE790EB4612A940470A1A5D7464F451811";
		 String dgi8203_exponent1_DmodP1 = "9B284298DA62E3EC43A54F63E3AFFEF05A088C85D34590E37142A41B3C59D0E0B59A16B56B331C200B68BB32DDE94E3F";
		 String dgi8202_exponent2_DmodQ1 = "929FCF5172136C7F76D052EAB1E655126518B7611D67F631490B72042F1DB9C9A609CD961C62ADA06BC3E4D98A2E100B";
		 String dgi8201_coefficient		 = "282BAE850F3A215BBAB948FE057CCBC8372F8E465BECEBD0CA8ACF1E0D53E4A5ADE1851C83A200F0D74903F349BB1758";



         RSAPrivateCrtKeySpec   caPrivKeySpec = new RSAPrivateCrtKeySpec(
                 new BigInteger("C7F317AFC57A6975E28F5631CBAB89B0AEA779D2FBFF9B6B0A54AE88CFDC7BD72C128291C9AFFF38663F856BCA8B18BB492465D2354A00B9228FADCCDDE8279391B8A8DF0F28E38122CE1C4120495775FFCFABD93172BAA5EB09E44B5D59334F", 16),
                 new BigInteger("3", 16),
                 new BigInteger("854CBA752E519BA3EC5F8ECBDD1D0675C9C4FBE1FD5512475C38745B353DA7E4C80C570BDBCAAA25997FAE47DC5CBB26585031F72C65B00FB1EA26E4A904710A4CAF2CADC41865EC0790A76154B95A4EF99138EFEEB6B2AE2584A2D080CEC3EB", 16),
                 new BigInteger("E8BC63E5479455E26577F715D587FE68870CD2C8BCE8595529E3F628DA86B9511067221020CCAA30111D18CC4CDDF55F", 16),  //PRIME_P, SETP (DGI-8205)
                 new BigInteger("DBEFB6FA2B1D22BF32387C600AD97F9B97A51311AC1BF149ED912B0646AC96AE790EB4612A940470A1A5D7464F451811", 16),  //PRIME_Q, SETQ (DGI-8204)
                 new BigInteger("9B284298DA62E3EC43A54F63E3AFFEF05A088C85D34590E37142A41B3C59D0E0B59A16B56B331C200B68BB32DDE94E3F", 16),  //PRIME_EXPONENT_P, SETDP1 (DGI-8203)
                 new BigInteger("929FCF5172136C7F76D052EAB1E655126518B7611D67F631490B72042F1DB9C9A609CD961C62ADA06BC3E4D98A2E100B", 16),  //PRIME_EXPONENT_Q, SETDQ1 (DGI-8202)
                 new BigInteger("282BAE850F3A215BBAB948FE057CCBC8372F8E465BECEBD0CA8ACF1E0D53E4A5ADE1851C83A200F0D74903F349BB1758", 16)); //CRT_COEFFICIENT, SETPQ  (DGI-8201)
		*/

        RSAPrivateCrtKeySpec caPrivKeySpec = new RSAPrivateCrtKeySpec(
                new BigInteger(dgi8103_modulusN, baseConversion_radix),            //MODULUS N (DGI-8103)
                new BigInteger(tag9F47_publicExponentE, baseConversion_radix),        //PUBLIC EXPONENT E tag '9F47'
                new BigInteger(dgi8101_privateExponentD, baseConversion_radix),    //PRIVATE EXPONENT D (DGI-8101)
                new BigInteger(dgi8205_prime1P, baseConversion_radix),            //PRIME_P, SETP (DGI-8205)
                new BigInteger(dgi8204_prime2Q, baseConversion_radix),            //PRIME_Q, SETQ (DGI-8204)
                new BigInteger(dgi8203_exponent1_DmodP1, baseConversion_radix),    //PRIME_EXPONENT_P, SETDP1 (DGI-8203)
                new BigInteger(dgi8202_exponent2_DmodQ1, baseConversion_radix),    //PRIME_EXPONENT_Q, SETDQ1 (DGI-8202)
                new BigInteger(dgi8201_coefficient, baseConversion_radix));        //CRT_COEFFICIENT, SETPQ  (DGI-8201)


        //hendy
         /*
         byte[] tmpSDADBuffer2 = new byte [] {
 	            (byte)0x6A, // 0	data header
 	            (byte)0x95, // 1	arqc
 	            (byte)0x01, // 2	sha-1
 	            (byte)0x03, // 3	length dynamic data
 	            (byte)0x02, // 4	dynamic data
 	            (byte)0x00, // 5	atc
 	            (byte)0x03, // 6
 	            (byte)0xbb, (byte)0xbb,  (byte)0xbb, //7 8 9	padding from 7-74
 	            (byte)0xbb,  (byte)0xbb,  (byte)0xbb,  (byte)0xbb,  (byte)0xbb,  (byte)0xbb,  (byte)0xbb,  (byte)0xbb,  (byte)0xbb,  (byte)0xbb,    //10-19	padding
 	            (byte)0xbb,  (byte)0xbb,  (byte)0xbb,  (byte)0xbb,  (byte)0xbb,  (byte)0xbb,  (byte)0xbb,  (byte)0xbb,  (byte)0xbb,  (byte)0xbb, 	//20-29 padding
 	            (byte)0xbb,  (byte)0xbb,  (byte)0xbb,  (byte)0xbb,  (byte)0xbb,  (byte)0xbb,  (byte)0xbb,  (byte)0xbb,  (byte)0xbb,  (byte)0xbb, 	//30-39	padding
 	            (byte)0xbb,  (byte)0xbb,  (byte)0xbb,  (byte)0xbb,  (byte)0xbb,  (byte)0xbb,  (byte)0xbb,  (byte)0xbb,  (byte)0xbb,  (byte)0xbb, 	//40-49 padding
 	            (byte)0xbb,  (byte)0xbb,  (byte)0xbb,  (byte)0xbb,  (byte)0xbb,  (byte)0xbb,  (byte)0xbb,  (byte)0xbb,  (byte)0xbb,  (byte)0xbb, 	//50-59 padding
 	            (byte)0xbb,  (byte)0xbb,  (byte)0xbb,  (byte)0xbb,  (byte)0xbb,  (byte)0xbb,  (byte)0xbb,  (byte)0xbb,  (byte)0xbb,  (byte)0xbb, 	//60-69 padding
 	            (byte)0xbb,  (byte)0xbb,  (byte)0xbb,  (byte)0xbb,  (byte)0xbb, 																    //70-74 padding
 	            (byte)0x12,  (byte)0x34,  (byte)0x56,  (byte)0x78,  							//9F37 - terminal unpredictable number 	(Terminal dynamic data)
 	            (byte)0x00,  (byte)0x00,  (byte)0x00,  (byte)0x00,   (byte)0x01,  (byte)0x00,	//9F02 - terminal amount authorized 	(Terminal dynamic data)
 	            (byte)0x08,  (byte)0x40,  														//5F2A - transaction currency code 		(Terminal dynamic data)
 	            (byte)0x01,  																	//fDDA version number 					(Card authentication related data)
 	            (byte)0x05,  (byte)0x06,  (byte)0x07,  (byte)0x08,  							//card unpredictable number 			(Card authentication related data)
 	            (byte)0x00,  (byte)0x00,   														//card transaction qualifiers			(Card authentication related data)
 	            (byte)0x00,  (byte)0x00   														//94 95
 	    };
         */

        try {
			 /*
			 byte a1[], b1[], c1[], d1[], e1[], f1[],g1[],h1[];
	         BigInteger a = caPrivKeySpec.getPrimeP();
	         BigInteger b = caPrivKeySpec.getPrimeQ();
	         BigInteger c = caPrivKeySpec.getPrimeExponentP();
	         BigInteger d = caPrivKeySpec.getPrimeExponentQ();
	         BigInteger e = caPrivKeySpec.getCrtCoefficient();

	         BigInteger f = caPrivKeySpec.getModulus();
	         BigInteger g = caPrivKeySpec.getPrivateExponent();


	         a1 = a.toByteArray();	//0-63 bytes
	         b1 = b.toByteArray();
	         c1 = c.toByteArray();
	         d1 = d.toByteArray();
	         e1 = e.toByteArray();

	         f1 = c.toByteArray();
	         g1 = d.toByteArray();
			 */

            // Prepare signed data ('9F4B')
            // Use entire buffer
            short dataOffset = (short) 0;

            // Header byte
            tmpSDADBuffer[dataOffset] = (byte) 0x6A;
            dataOffset++;
            Util.setShort(tmpSDADBuffer, (short) (dataOffset), (short) 0x9501);
            dataOffset += 2;
            Util.setShort(tmpSDADBuffer, (short) (dataOffset), (short) 0x0302);
            dataOffset += 2;
            Util.setShort(tmpSDADBuffer, (short) (dataOffset), (short) ATC);
            dataOffset += 2;

            Arrays.fill(tmpSDADBuffer, dataOffset, 75, (byte) 0xbb);
            dataOffset += 75;
            dataOffset -= 7;
            hashOffset = dataOffset;    //75

            Util.arrayCopy(commandApdu, GPO_Data_Offsets_CL[GPO_DO_UNP_NBR], tmpSDADBuffer, dataOffset, (short) 4);
            dataOffset += 4;
            Util.arrayCopy(commandApdu, GPO_Data_Offsets_CL[GPO_DO_AMOUNT], tmpSDADBuffer, dataOffset, (short) 6);
            dataOffset += 6;
            Util.arrayCopy(commandApdu, GPO_Data_Offsets_CL[GPO_DO_TRAN_CC], tmpSDADBuffer, dataOffset, (short) 2);
            dataOffset += 2;
            tmpSDADBuffer[dataOffset++] = (byte) 0x01;    //fDDA version number

            cardUnpredNumber = new byte[4];
            Random rand = new Random();
            rand.nextBytes(cardUnpredNumber);
            Util.arrayCopy(cardUnpredNumber, (short) 0, tmpSDADBuffer, dataOffset, (short) 4);
            dataOffset += 4;
            Util.arrayCopy(Tag_QVSDC_CTQ, (short) 0, tmpSDADBuffer, dataOffset, (short) 2);
            dataOffset += 2;

            //compute message digest and generate hash computation
            MessageDigestRSA = MessageDigest.getInstance("SHA");
            MessageDigestRSA.update(tmpSDADBuffer, 1, 93);    //todo hendy
            byte[] digest = MessageDigestRSA.digest();    //04, aa, ae, 9e,...,80,52,d3

            Util.arrayCopy(digest, (short) 0, tmpSDADBuffer, (short) hashOffset, (short) digest.length);

            // Trailer
            tmpSDADBuffer[(short) (hashOffset + 20)] = (byte) 0xBC;

            // Create an RSA private key from the CRT specification
            KeyFactory kf = KeyFactory.getInstance("RSA");
            RSAPrivateCrtKey rsaPriKey = (RSAPrivateCrtKey) kf.generatePrivate(caPrivKeySpec);
		     /*
		     	 PrivateKey java.security.KeyFactory.generatePrivate(KeySpec keySpec) throws InvalidKeySpecException
		  	     Generates a instance of PrivateKey from the given key specification.
			     Parameters:
			     keySpec the specification of the private key.
			     Returns:
			     the private key
		     */

            cipherRSA = Cipher.getInstance("RSA/None/NoPadding");
            cipherRSA.init(cipherRSA.ENCRYPT_MODE, (RSAPrivateCrtKey) rsaPriKey);

            byte[] signature = cipherRSA.doFinal(tmpSDADBuffer);
            Util.arrayCopy(signature, (short) 0, tmpSDADBuffer, (short) 0, (short) signature.length);


        } catch (NoSuchAlgorithmException e) {
            // TODO Auto-generated catch block;
            e.printStackTrace();

        } catch (InvalidKeyException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (InvalidKeySpecException e2) {
            // TODO Auto-generated catch block
            e2.printStackTrace();
        } catch (NoSuchPaddingException e2) {
            // TODO Auto-generated catch block
            e2.printStackTrace();
        } catch (IllegalBlockSizeException e2) {
            // TODO Auto-generated catch block
            e2.printStackTrace();
        } catch (BadPaddingException e2) {
            // TODO Auto-generated catch block
            e2.printStackTrace();
        }
        return returnVal;

    }


    private void retrieve_XMLfile(String fullPath_fileName) throws IOException {

        //DebugActivity.sendLog("VCBPAProcess:  retrieve_XMLfile", " open " + fullPath_fileName);

        InputStream fileIS = null;
        String line = null;
        byte[] inputBuffer = new byte[MAXAPDU_SIZE];
        fullPath_fileName = "./AccountParameters.xml";

        try {
            fileIS = new FileInputStream(fullPath_fileName);
            BufferedReader reader = new BufferedReader(new InputStreamReader(fileIS));
            while ((line = reader.readLine()) != null) {
                //DebugActivity.sendLog("VCBPAProcess:  retrieve_XMLfile data: ", line);
                inputBuffer = Util.convertToBytes(line);

            }

        } catch (IOException e) {
            //DebugActivity.sendLog("VCBPAProcess: retrieve_XMLfile", " Failed on " + fullPath_fileName);
        } finally {
            if (fileIS != null) {
                fileIS.close();
                //DebugActivity.sendLog("VCBPAProcess:  retrieve_XMLfile", " close " + fullPath_fileName);
            }
        }
    }

}