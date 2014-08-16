/**
 * Copyright 2013 Ministerio de Industria, EnergÃ­a y Turismo
 *
 * Este fichero es parte de "Componentes de Firma XAdES 1.1.7".
 *
 * Licencia con arreglo a la EUPL, VersiÃ³n 1.1 o â€“en cuanto sean aprobadas por la ComisiÃ³n Europeaâ€“ versiones posteriores de la EUPL (la Licencia);
 * Solo podrÃ¡ usarse esta obra si se respeta la Licencia.
 *
 * Puede obtenerse una copia de la Licencia en:
 *
 * http://joinup.ec.europa.eu/software/page/eupl/licence-eupl
 *
 * Salvo cuando lo exija la legislaciÃ³n aplicable o se acuerde por escrito, el programa distribuido con arreglo a la Licencia se distribuye Â«TAL CUALÂ»,
 * SIN GARANTÃ�AS NI CONDICIONES DE NINGÃšN TIPO, ni expresas ni implÃ­citas.
 * VÃ©ase la Licencia en el idioma concreto que rige los permisos y limitaciones que establece la Licencia.
 */
package com.accioma.eris.sign.xades;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.Document;
import org.xml.sax.SAXException;

import es.mityc.firmaJava.libreria.xades.DataToSign;
import es.mityc.firmaJava.libreria.xades.FirmaXML;
import es.mityc.firmaJava.libreria.xades.XAdESSchemas;
import es.mityc.firmaJava.role.SimpleClaimedRole;
import es.mityc.javasign.EnumFormatoFirma;
import es.mityc.javasign.issues.PassStoreKS;
import es.mityc.javasign.pkstore.CertStoreException;
import es.mityc.javasign.pkstore.IPKStoreManager;
import es.mityc.javasign.pkstore.keystore.KSStore;
import es.mityc.javasign.xml.refs.InternObjectToSign;
import es.mityc.javasign.xml.refs.ObjectToSign;

/**
 * <p>
 * Clase de ejemplo para la firma XAdES-BES enveloped de un documento
 * </p>
 * <p>
 * Para realizar la firma se utilizarÃ¡ el almacÃ©n PKCS#12 definido en la
 * constante <code>GenericXMLSignature.PKCS12_FILE</code>, al que se accederÃ¡
 * mediante la password definida en la constante
 * <code>GenericXMLSignature.PKCS12_PASSWORD</code>. El directorio donde quedarÃ¡
 * el archivo XML resultante serÃ¡ el indicado en al constante
 * <code>GenericXMLSignature.OUTPUT_DIRECTORY</code>
 * </p>
 * 
 */
public class XAdESBESCoSignature extends GenericXMLSignature {

    /**
     * <p>
     * Recurso a firmar
     * </p>
     */
    //private final static String RESOURCE_TO_SIGN = "XAdES-BES-Sign.xml";
	//private final static String RESOURCE_TO_SIGN = "/home/marcelo/Documents/Eris/sign_test/XAdES-BES-Sign_01.xml";
    /**
     * <p>
     * Fichero donde se desea guardar la firma
     * </p>
     */
    //private final static String SIGN_FILE_NAME = "/home/marcelo/Documents/Eris/sign_test/XAdES-BES-CoSign.xml";
	//private final static String SIGN_FILE_NAME = "XAdES-BES-CoSign.xml";
    /**
     * <p>
     * Punto de entrada al programa
     * </p>
     * 
     * @param args
     *            Argumentos del programa
     */
	private final String unsignedDocFilename;
	private final String signedDocFilename;
	private final String signedDocPath;
	private final String signFilename;
	private final String id2Sign;
	private final String name2Sign;
	private final String type2Sign;
	
	
	
	public XAdESBESCoSignature(String unsignedDocFilename
			, String signedDocFilename
			, String signedDocPath
			, String signFilename
			, String password
			, String id2Sign
			, String name2Sing
			, String type2Sign
			){
		
		this.unsignedDocFilename = unsignedDocFilename;
		this.signedDocFilename = signedDocFilename;
		this.signedDocPath = signedDocPath;
		this.signFilename = signFilename;
		this.id2Sign = id2Sign;
		this.name2Sign = name2Sing;
		this.type2Sign = type2Sign;
		
		super.PKCS12_RESOURCE = signFilename;
		super.PKCS12_PASSWORD = password;
		super.OUTPUT_DIRECTORY = signedDocPath;
		
	}
	/*
    public static void main(String[] args) {
    	// Se obtiene la firma XAdES a contrafirmar, resultado del proceso de firma de nivel XAdES-BES
    	File f = new File(RESOURCE_TO_SIGN);
    	if (f == null || !f.exists()) {
    		System.err.println("No se encuentra la firma a cofirmar: " + f.getAbsolutePath()
    				+ "\nEjecute en primer lugar el ejemplo de firma de nivel XAdES-BES");
    		return;
    	}
        
        // Se contrafirma la firma previamente generada
        XAdESBESCoSignature coSignature = new XAdESBESCoSignature();
        coSignature.execute();
    }
	*/
	
    @Override
    protected DataToSign createDataToSign() {
        DataToSign dataToSign = new DataToSign();
        dataToSign.setXadesFormat(EnumFormatoFirma.XAdES_BES);
        dataToSign.setEsquema(XAdESSchemas.XAdES_132);
        dataToSign.setXMLEncoding("UTF-8");
        // Se aÃ±ade un rol de firma
        dataToSign.addClaimedRol(new SimpleClaimedRole("Rol de contrafirma"));
        //dataToSign.addObject(new ObjectToSign(new InternObjectToSign("documento"), "Documento de ejemplo", null, "text/xml", null));
        dataToSign.addObject(new ObjectToSign(new InternObjectToSign(id2Sign), name2Sign, null, type2Sign, null));
        dataToSign.setEnveloped(true);
        Document docToSign = getDocument(unsignedDocFilename);
        dataToSign.setDocument(docToSign);
        return dataToSign;
    }
    
    /**
     * <p>
     * EjecuciÃ³n del ejemplo. La ejecuciÃ³n consistirÃ¡ en la firma de los datos
     * creados por el mÃ©todo abstracto <code>createDataToSign</code> mediante el
     * certificado declarado en la constante <code>PKCS12_FILE</code>. El
     * resultado del proceso de firma serÃ¡ almacenado en un fichero XML en el
     * directorio correspondiente a la constante <code>OUTPUT_DIRECTORY</code>
     * del usuario bajo el nombre devuelto por el mÃ©todo abstracto
     * <code>getSignFileName</code>
     * </p>
     */
    @Override
    public void execute() {

        // Obtencion del gestor de claves
        IPKStoreManager storeManager = getPKStoreManager();
        if (storeManager == null) {
            System.err.println("El gestor de claves no se ha obtenido correctamente.");
            return;
        }

        // Obtencion del certificado para firmar. Utilizaremos el primer
        // certificado del almacen.
        X509Certificate certificate = getFirstCertificate(storeManager);
        if (certificate == null) {
            System.err.println("No existe ningun certificado para firmar.");
            return;
        }

        /*
         * CreaciÃ³n del objeto que contiene tanto los datos a firmar como la
         * configuraciÃ³n del tipo de firma
         */
        DataToSign dataToSign = createDataToSign();

        // Firmamos el documento
        try {
            FirmaXML firma = new FirmaXML();
            firma.signFile(
            		certificate,		// Certificado firmante. Se toma el primero de entre los disponibles
            		dataToSign,			// ConfiguraciÃ³n de firma
            		storeManager,		// KeyStore para el acceso a la clave privada
            		signedDocPath,	// Ruta donde se guardarÃ¡ la firma generada
            		File.separatorChar + signedDocFilename);	// Nombre de la firma generada
        } catch (Exception ex) {
            System.err.println("Error realizando la firma");
            ex.printStackTrace();
            return;
        }

        // Guardamos la firma a un fichero en el home del usuario
        String filePath = signedDocPath + File.separatorChar + signedDocFilename;
        System.out.println("Firma salvada en en: " + filePath);
    }
    
    public void sign(){
    	execute();
    }

    /**
     * <p>
     * Devuelve el <code>Document</code> correspondiente al
     * <code>resource</code> pasado como parÃ¡metro
     * </p>
     * 
     * @param resource
     *            El recurso que se desea obtener
     * @return El <code>Document</code> asociado al <code>resource</code>
     */
    @Override
    protected Document getDocument(String resource) {
        Document doc = null;
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        try {
            doc = dbf.newDocumentBuilder().parse(new FileInputStream(resource));
        } catch (ParserConfigurationException ex) {
            System.err.println("Error al parsear el documento");
            ex.printStackTrace();
            System.exit(-1);
        } catch (SAXException ex) {
            System.err.println("Error al parsear el documento");
            ex.printStackTrace();
            System.exit(-1);
        } catch (IOException ex) {
            System.err.println("Error al parsear el documento");
            ex.printStackTrace();
            System.exit(-1);
        } catch (IllegalArgumentException ex) {
            System.err.println("Error al parsear el documento");
            ex.printStackTrace();
            System.exit(-1);
        }
        return doc;
    }

    /**
     * <p>
     * Devuelve el gestor de claves que se va a utilizar
     * </p>
     * 
     * @return El gestor de claves que se va a utilizar</p>
     */
    private IPKStoreManager getPKStoreManager() {
        IPKStoreManager storeManager = null;
        try {
        	/*
        	 * TODO: Pasar a un archivo properties la ubicacion de la firma y el password
        	 * El password esta en el keystore y en el storeManager
        	 */
            KeyStore ks = KeyStore.getInstance("PKCS12");
        	//KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            //ks.load(this.getClass().getResourceAsStream(PKCS12_RESOURCE), PKCS12_PASSWORD.toCharArray());
            //InputStream readStream = new FileInputStream("/home/marcelo/Documents/Eris/sign_test/danilo_german_cabrera_casamin.p12");
            InputStream readStream = new FileInputStream(signFilename);
            //InputStream readStream = new FileInputStream("/home/marcelo/Documents/Eris/sign_test/usr0061.p12");
            //ks.load(this.getClass().getResourceAsStream(PKCS12_RESOURCE), PKCS12_PASSWORD.toCharArray());
            ks.load(readStream, PKCS12_PASSWORD.toCharArray());
            //ks.load(readStream, "usr0061".toCharArray());
            //storeManager = new KSStore(ks, new PassStoreKS(PKCS12_PASSWORD));
            storeManager = new KSStore(ks, new PassStoreKS(PKCS12_PASSWORD));
        } catch (KeyStoreException ex) {
            System.err.println("No se puede generar KeyStore PKCS12");
            ex.printStackTrace();
            System.exit(-1);
        } catch (NoSuchAlgorithmException ex) {
            System.err.println("No se puede generar KeyStore PKCS12");
            ex.printStackTrace();
            System.exit(-1);
        } catch (CertificateException ex) {
            System.err.println("No se puede generar KeyStore PKCS12");
            ex.printStackTrace();
            System.exit(-1);
        } catch (IOException ex) {
            System.err.println("No se puede generar KeyStore PKCS12");
            ex.printStackTrace();
            System.exit(-1);
        }
        return storeManager;
    }

    /**
     * <p>
     * Recupera el primero de los certificados del almacÃ©n.
     * </p>
     * 
     * @param storeManager
     *            Interfaz de acceso al almacÃ©n
     * @return Primer certificado disponible en el almacÃ©n
     */
    private X509Certificate getFirstCertificate(
            final IPKStoreManager storeManager) {
        List<X509Certificate> certs = null;
        try {
            certs = storeManager.getSignCertificates();
        } catch (CertStoreException ex) {
            System.err.println("Fallo obteniendo listado de certificados");
            System.exit(-1);
        }
        if ((certs == null) || (certs.size() == 0)) {
            System.err.println("Lista de certificados vacÃ­a");
            System.exit(-1);
        }

        X509Certificate certificate = certs.get(0);
        return certificate;
    }

	@Override
	protected String getSignatureFileName() {
		return File.separatorChar + signedDocFilename;
	}
	
	public String testFunc(){
		return new String("Test Func");
	}
}
