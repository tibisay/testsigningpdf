package holamundopdf;


import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.Console;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;

import com.itextpdf.text.Anchor;
import com.itextpdf.text.BadElementException;
import com.itextpdf.text.BaseColor;
import com.itextpdf.text.Chapter;
import com.itextpdf.text.Document;
import com.itextpdf.text.DocumentException;
import com.itextpdf.text.Element;
import com.itextpdf.text.Font;
import com.itextpdf.text.List;
import com.itextpdf.text.ListItem;
import com.itextpdf.text.Paragraph;
import com.itextpdf.text.Phrase;
import com.itextpdf.text.Rectangle;
import com.itextpdf.text.Section;
import com.itextpdf.text.pdf.PdfDate;
import com.itextpdf.text.pdf.PdfDictionary;
import com.itextpdf.text.pdf.PdfName;
import com.itextpdf.text.pdf.PdfPCell;
import com.itextpdf.text.pdf.PdfPTable;
import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfSignature;
import com.itextpdf.text.pdf.PdfSignatureAppearance;
import com.itextpdf.text.pdf.PdfStamper;
import com.itextpdf.text.pdf.PdfString;
import com.itextpdf.text.pdf.PdfWriter;
import com.itextpdf.text.pdf.security.DigestAlgorithms;
import com.itextpdf.text.pdf.security.ExternalDigest;
import com.itextpdf.text.pdf.security.MakeSignature.CryptoStandard;
import com.itextpdf.text.pdf.security.PdfPKCS7;
import com.sun.org.apache.xml.internal.security.utils.Base64;



// https://joinup.ec.europa.eu/svn/cbds/java/pdf-signer/src/main/java/ee/smartlink/PDFSigner.java
// https://javaemvreader.googlecode.com/svn-history/r20/trunk/src/main/java/sasc/util/Util.java



public class FirstPDF {
  // ruta absoluta al archivo pdf que se desea firmar
  private static String FILE = "/tmp/resenaProyectoTibisay.pdf";
  
  // ruta abosluta del archivo .pem que contiene el certificado electronico del 
  // firmante
  private static String CERTFILE = "/tmp/SimonDiaz.pem";
  
  // ruta absoluta del archivo pdf firmado
  private static String DEST = "/tmp/firmado.pdf";

  public static void main(String[] args) {
	  
	  if (args.length != 3)
	  {

		  System.out.println("Modo de Uso:");
          System.out.println("\t java -jar holamundopdf.jar /ruta/abosluta/archivo/pdf /ruta/abosluta/certificado/firmante /ruta/abosluta/archivo/firmado");
          System.exit(0);
	  }

	  FILE = args[0];	  
	  CERTFILE = args[1];
	  DEST = args[2];

	  try {

    	// obtener el certificado del firmante
    	FileInputStream fis = new FileInputStream(CERTFILE);
    	BufferedInputStream bis = new BufferedInputStream(fis);
    	
    	CertificateFactory factory = CertificateFactory.getInstance("X.509");
    	//Certificate[] chain = new Certificate[1];
    	Certificate cert = null;
    	
    	while (bis.available() > 0) {
    	    cert = factory.generateCertificate(bis);
    	    //System.out.println(cert.toString());
    	 }
    	Certificate[] chain = new Certificate[1];
    	chain[0] = cert;

    	System.out.println(cert.toString());
    	
    	// crear un reader y un stamper
    	PdfReader reader = new PdfReader(FILE);
    	//ByteArrayOutputStream baos = new ByteArrayOutputStream();
    	//PdfStamper stamper = PdfStamper.createSignature(reader, baos, '\0');
    	
    	FileOutputStream fout = new FileOutputStream(DEST);
    	PdfStamper stamper = PdfStamper.createSignature(reader, fout, '\0');
    	
    	// crear la apariencia de la firma
    	PdfSignatureAppearance sap = stamper.getSignatureAppearance();
    	sap.setReason("Prueba de firma en dos partes");
    	sap.setLocation("Merida, Venezuela");
    	sap.setVisibleSignature(new Rectangle(36, 748, 144,780),1, "sig");
    	sap.setCertificate(cert);
    	
    	// crear la estructura de la firma
    	PdfSignature dic = new PdfSignature(PdfName.ADOBE_PPKLITE, PdfName.ADBE_PKCS7_DETACHED);
    	dic.setReason(sap.getReason());
    	dic.setLocation(sap.getLocation());
    	dic.setContact(sap.getContact());
    	dic.setDate(new PdfDate(sap.getSignDate()));
    	
    	sap.setCryptoDictionary(dic);
    	
    	HashMap<PdfName, Integer> exc = new HashMap<PdfName, Integer> ();
    	exc.put(PdfName.CONTENTS, new Integer(8192 * 2 + 2));
    	sap.preClose(exc);
    	
    	ExternalDigest externalDigest = new ExternalDigest() {
    		public MessageDigest getMessageDigest(String hashAlgorithm)
    		throws GeneralSecurityException {
    			return DigestAlgorithms.getMessageDigest(hashAlgorithm, null);
    		}
    	};
    	
    	PdfPKCS7 sgn = new PdfPKCS7(null, chain, "SHA256", null, externalDigest, false);
    	
    	InputStream data = sap.getRangeStream();
    	
    	byte hash[] = DigestAlgorithms.digest(data, externalDigest.getMessageDigest("SHA256"));
    	
    	Calendar cal = Calendar.getInstance();
    	byte sh[] = sgn.getAuthenticatedAttributeBytes(hash, cal, null, null, CryptoStandard.CMS);
    	
    	sh = DigestAlgorithms.digest(new ByteArrayInputStream(sh), externalDigest.getMessageDigest("SHA256"));
    	
    	System.out.println("sh length: "+ sh.length);
    	    	
    	String hashToSign2 = byteArrayToHexString(sh);
    	System.out.println("***************************************************************");
    	System.out.println("HASH EN HEXADECIMAL:");
    	System.out.println(hashToSign2);
    	System.out.println("length: " +hashToSign2.length());	
    	System.out.println("***************************************************************");
    	  		
    	Console console = System.console();
    	if (console == null) {
    		System.err.println("No console.");
    	    System.exit(1);
    	}
    	    	
    	String signature = console.readLine("Introduzca la firma generada con el hardware: ");
    	
    	System.out.println("");
    	System.out.println("Firma creada en el hardware");
    	System.out.println(signature);
    	
    	// convertir signature (hesadecimal) en bytes []
    	byte[] signedHash = null;
    	signedHash = new BigInteger(signature,16).toByteArray();
    	
    	// postsign    	
    	sgn.setExternalDigest(signedHash, null, "RSA");
    	byte[] encodedSig = sgn.getEncodedPKCS7(hash, cal, null, null, null, CryptoStandard.CMS);
    	byte[] paddedSig = new byte[8192];
    	
    	System.arraycopy(encodedSig, 0, paddedSig, 0, encodedSig.length);
        PdfDictionary dic2 = new PdfDictionary();
    	
        dic2.put(PdfName.CONTENTS, new PdfString(paddedSig).setHexWriting(true));
        //sap.close(dic2);
    	
        try{
        	sap.close(dic2);
        }catch(DocumentException e){
        	throw new IOException(e);
        }
        
        stamper.close();
   
    	System.out.println("archivo: "+DEST+ " firmado exitosamente.");
      
    } catch (Exception e) {
      e.printStackTrace();
    } 
  }

  
  /**
   * Converts a byte array into a hex string.
   * @param byteArray the byte array source
   * @return a hex string representing the byte array
   */
  public static String byteArrayToHexString(final byte[] byteArray) {
      if (byteArray == null) {
          return "";
      }
      return byteArrayToHexString(byteArray, 0, byteArray.length);
  }
  
  public static String byteArrayToHexString(final byte[] byteArray, int startPos, int length) {
      if (byteArray == null) {
          return "";
      }
      if(byteArray.length < startPos+length){
          throw new IllegalArgumentException("startPos("+startPos+")+length("+length+") > byteArray.length("+byteArray.length+")");
      }
//      int readBytes = byteArray.length;
      StringBuilder hexData = new StringBuilder();
      int onebyte;
      for (int i = 0; i < length; i++) {
          onebyte = ((0x000000ff & byteArray[startPos+i]) | 0xffffff00);
          hexData.append(Integer.toHexString(onebyte).substring(6));
      }
      return hexData.toString();
  }

    
  
} 