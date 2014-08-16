package com.accioma.eris.sign.xades;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

public class Signer {

	public static void main(String[] args) {
		String docfilename = null;
		String id2Sign = null;
		String name2Sign = null;
		String type2Sign = null;
		
		if( args.length < 1){
			System.out.println("Por favor especifique una accion");
			System.exit(0);
		}
		
		if(args[0].equals("encrypt") ){
			System.out.println(DesEncrypt.encrypt(args[1]));
			System.exit(0);
		}
		
		if(args[0].equals("decrypt") ){
			System.out.println(DesEncrypt.decrypt(args[1]));
			System.exit(0);
		}
		
		if(args[0].equals("sign")){
			Properties props = new Properties();
			InputStream is = null;
			if(args.length < 2){
				System.exit(0);
			}
			docfilename = args[2];
			id2Sign = args[1];
			if(id2Sign.equals("comprobante")){
				name2Sign = "Comprobante";
				type2Sign = "text/xml";
			}else if(id2Sign.equals("lote")){
				name2Sign = "Lote";
				type2Sign = "text/xml";
			}
			
			try{
				is = new FileInputStream("config.properties");
				props.load(is);
				String unsignedDocsFolder = props.getProperty("unsigned_docs_folder");
				String signedDocsFolder = props.getProperty("signed_docs_folder");
				String signFilename = props.getProperty("sign_filename");
				//Password del archivo
				String password = DesEncrypt.decrypt(props.getProperty("sign_password"));
				System.out.println("Firmando el archivo: " + docfilename);
				System.out.println("Ubicado en: " + props.getProperty("unsigned_docs_folder"));
				File docFile = new File(new File(unsignedDocsFolder), docfilename);
				System.out.println(docFile.getPath());
				
				XAdESBESCoSignature signer = new XAdESBESCoSignature(docFile.getPath()
						, docfilename
						, signedDocsFolder
						, signFilename
						, password
						, id2Sign
						, name2Sign
						, type2Sign
						);
				signer.execute();
				docFile.delete();
			}catch(IOException ioex){
				ioex.printStackTrace();
			}finally{
				if(is!=null){
					try{
						is.close();
					}catch(IOException ex){
						ex.printStackTrace();
					}
				}
			}
		}

	}

}
