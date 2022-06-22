import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.file.DirectoryStream;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.Scanner;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;



class AES {
	private static SecretKeySpec secretKey;
	private static byte[] key;
	String secretKeyTag = "";
	
	AES(String scrtKy){
		secretKeyTag=scrtKy;
	}
	
	
	public void setKey(final String myKey) {
	    MessageDigest sha = null;
	    try {
	      key = myKey.getBytes("UTF-8");
	      sha = MessageDigest.getInstance("SHA-1");
	      key = sha.digest(key);
	      key = Arrays.copyOf(key, 16);
	      secretKey = new SecretKeySpec(key, "AES");
	    } catch (NoSuchAlgorithmException | UnsupportedEncodingException e) {
	      e.printStackTrace();
	    }
	  }
	
	public String encrypt(final String strToEncrypt, final String secret) {
	    try {
	      setKey(secret);
	      Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
	      cipher.init(Cipher.ENCRYPT_MODE, secretKey);
	      return Base64.getEncoder()
	        .encodeToString(cipher.doFinal(strToEncrypt.getBytes("UTF-8")));
	    } catch (Exception e) {
	      System.out.println("Error while encrypting: " + e.toString());
	    }
	    return null;
	  }
	
	public String decrypt(final String strToDecrypt, final String secret) {
	    try {
	      setKey(secret);
	      Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
	      cipher.init(Cipher.DECRYPT_MODE, secretKey);
	      return new String(cipher.doFinal(Base64.getDecoder()
	        .decode(strToDecrypt)));
	    } catch (Exception e) {
	      //System.out.println("Error while decrypting: " + e.toString());
	    	return "null";
	    }
	    
	  }

}


///////////////////////////////////////////////////////////////////////////////////////////////////////
public class BasicHostIDS {
	
	static Scanner sc=new Scanner(System.in);
	static ArrayList<String> arrOfLastModified = new ArrayList<String>();
	static ArrayList<String> arrOfFileNameForLM = new ArrayList<String>();
	
	
	public static Set<String> listFilesUsingFileWalkAndVisitor(String dir,String usrKy) throws IOException {
		arrOfLastModified.clear();
		arrOfFileNameForLM.clear();
		AES aes = new AES(usrKy);
        Set<String> fileList = new HashSet<>();
        Files.walkFileTree(Paths.get(dir), new SimpleFileVisitor<Path>() {
            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                if (!Files.isDirectory(file)) {
                	String lastmodifiedStr=attrs.lastModifiedTime()+"";
                	String hash=aes.encrypt(Files.readString(file), usrKy);
                    fileList.add(file.getFileName()
                        .toString()+":"+hash);
                    arrOfLastModified.add(lastmodifiedStr);
                    arrOfFileNameForLM.add(file.getFileName().toString());
                }
                return FileVisitResult.CONTINUE;
            }
        });
        return fileList;
    }
	
	public static String[] convertHashToArr(Set<String> set) {
		String arr[] = new String[set.size()];
		int i=0;
        for(String ele:set){
          arr[i++] = ele;
        }
        return arr;
	}
	
	public static void printIdenticalFiles(String dir,String secretKeyIDS) {
		try {
			Set<String> listOfFiles = listFilesUsingFileWalkAndVisitor(dir,secretKeyIDS);
			String[] arrOfFiles=convertHashToArr(listOfFiles);
			ArrayList<String> arrOfContents = new ArrayList<String>();
			ArrayList<String> arrOfFileNames = new ArrayList<String>();
			
			for(int itr0=0;itr0<arrOfFiles.length;itr0++) {
				int indxColon=arrOfFiles[itr0].indexOf(":");
				String content = arrOfFiles[itr0].substring(indxColon+1);
				String fileName = arrOfFiles[itr0].substring(0,indxColon);
				arrOfFileNames.add(fileName);
				arrOfContents.add(content);
			}
			String allEqualFiles="";
			for(int itr1=0;itr1<arrOfFiles.length;itr1++) {
				String equalFiles=">"+arrOfFileNames.get(itr1)+">";
				String content=arrOfContents.get(itr1);
				for(int itr2=0;itr2<arrOfFiles.length;itr2++) {
					if(itr1!=itr2 && !allEqualFiles.contains(arrOfFileNames.get(itr2))) {
						if(arrOfContents.get(itr2).equals(content)) {
							equalFiles+=arrOfFileNames.get(itr2)+" ";
						}
					}
				}
				StringTokenizer st1 = new StringTokenizer(equalFiles, ">");
				int tokenCounter=0;
				String lastEqFiles="***Equals";
				for (int itoken = 1; st1.hasMoreTokens(); itoken++) {
					lastEqFiles+="->"+st1.nextToken();
					//System.out.println(st1.nextToken());
					tokenCounter=itoken;
				}
				int indxOfFirstSign=lastEqFiles.indexOf(">");
				String substr=lastEqFiles.substring(indxOfFirstSign+1);
				int indxOfSecSign=substr.indexOf(">");
				if(indxOfSecSign!=-1) {
					String finalLastEqFiles = lastEqFiles.replaceAll("->", " ");
					System.out.println(finalLastEqFiles);
				}
				allEqualFiles+=equalFiles;
			}
			
		} catch (IOException e1) {
			//e1.printStackTrace();
		}
	}
	
	public static void createCheckPoint(String dir, String secretKeyIDS) {
		AES aes = new AES(secretKeyIDS);
		try {
			Set<String> listOfFiles;
			listOfFiles = listFilesUsingFileWalkAndVisitor(dir,secretKeyIDS);
			String[] arrOfFiles=convertHashToArr(listOfFiles);
			ArrayList<String> arrOfContents = new ArrayList<String>();
			ArrayList<String> arrOfFileNames = new ArrayList<String>();
			for(int itr0=0;itr0<arrOfFiles.length;itr0++) {
				int indxColon=arrOfFiles[itr0].indexOf(":");
				String content = arrOfFiles[itr0].substring(indxColon+1);
				String fileName = arrOfFiles[itr0].substring(0,indxColon);
				arrOfFileNames.add(fileName);
				arrOfContents.add(content);
			}
			
			int checkPointCounter=0;
			for(int i=0;i<arrOfContents.size();i++) {
				if(arrOfFileNames.get(i).contains("IDScheckpointsensitive")) {
					checkPointCounter+=1;
				}
				//System.out.println(arrOfFileNames.get(i));
			}
			//System.out.print(checkPointCounter+":chckcounter");
			checkPointCounter+=1;
			String checkPointCounterStr=checkPointCounter+"";
			if(dir.endsWith("\\")) {}
			else {dir+="\\";}
			String checkPointFileName="IDScheckpoint"+checkPointCounterStr+".txt";
			String checkPointSensitiveFileName="IDScheckpointsensitive"+checkPointCounterStr+".txt";
			String checkPointPath=dir+checkPointFileName;
			String checkPointSensitivePath=dir+checkPointSensitiveFileName;
			//System.out.println(checkPointPath);
			//checkpoint content=  >cnr>file1name>cnr>content1>cnr>lastmodified1>cnr>
			//		asagý dogru		..	..	.	.	.	.	.	.	..	.
			FileWriter fw = new FileWriter(checkPointPath, true);
			FileWriter fwsensitive = new FileWriter(checkPointSensitivePath, true);
			String willEncryptCheckPoint=""; String willEncryptCheckPointSensitive="";
			for(int itrchckpnt=0;itrchckpnt<arrOfFileNames.size();itrchckpnt++) {
				String encryptedCheckPointContent=">cnr>"+arrOfFileNames.get(itrchckpnt)+">cnr>"+arrOfContents.get(itrchckpnt)+">cnr>"+System.lineSeparator();
				//encryptedCheckPointContent = aes.encrypt(encryptedCheckPointContent, secretKeyIDS);
				willEncryptCheckPoint+=encryptedCheckPointContent;
				//fw.write(encryptedCheckPointContent);
				for(int itrlstmdf=0;itrlstmdf<arrOfLastModified.size();itrlstmdf++) {
					if(arrOfFileNames.get(itrchckpnt).equals(arrOfFileNameForLM.get(itrlstmdf))) {
						String encryptedLastMdf=aes.encrypt(arrOfLastModified.get(itrlstmdf), secretKeyIDS);
						String encryptedCheckPointSensitiveContent=">cnr>"+arrOfFileNameForLM.get(itrlstmdf)+">cnr>"+encryptedLastMdf+">cnr>"+System.lineSeparator();
						//encryptedCheckPointSensitiveContent = aes.encrypt(encryptedCheckPointSensitiveContent, secretKeyIDS);
						willEncryptCheckPointSensitive+=encryptedCheckPointSensitiveContent;
						//fwsensitive.write(encryptedCheckPointSensitiveContent);
						break;
					}
				}
			}
			willEncryptCheckPoint=aes.encrypt(willEncryptCheckPoint, secretKeyIDS);
			willEncryptCheckPoint=aes.encrypt(willEncryptCheckPoint, secretKeyIDS);
			willEncryptCheckPointSensitive=aes.encrypt(willEncryptCheckPointSensitive, secretKeyIDS);
			willEncryptCheckPointSensitive=aes.encrypt(willEncryptCheckPointSensitive, secretKeyIDS);
			
			fw.write(willEncryptCheckPoint); fwsensitive.write(willEncryptCheckPointSensitive);
			fw.close(); fwsensitive.close();
			//Path pth = Paths.get(checkPointPath);
			//System.out.println(aes.decrypt(Files.readString(pth), secretKeyIDS));
			
			System.out.println("***Checkpoint created on path:"+checkPointPath);
			System.out.println("***Checkpointsensitive created on path:"+checkPointSensitivePath);
		} catch (IOException e) {
			//e.printStackTrace();
		}
		

		
	}
	
	
	public static void printModifiedFiles(String dir, String secretKeyIDS) {
		Scanner scmdf=new Scanner(System.in);
		AES aes = new AES(secretKeyIDS);
		try {
			Set<String> listOfFiles;
			listOfFiles = listFilesUsingFileWalkAndVisitor(dir,secretKeyIDS);
			String[] arrOfFiles=convertHashToArr(listOfFiles);
			ArrayList<String> arrOfContents = new ArrayList<String>();
			ArrayList<String> arrOfFileNames = new ArrayList<String>();
			for(int itr0=0;itr0<arrOfFiles.length;itr0++) {
				int indxColon=arrOfFiles[itr0].indexOf(":");
				String content = arrOfFiles[itr0].substring(indxColon+1);
				String fileName = arrOfFiles[itr0].substring(0,indxColon);
				arrOfFileNames.add(fileName);
				arrOfContents.add(content);
			}
			ArrayList<String> allCheckPoints = new ArrayList<String>();
			for(int i=0;i<arrOfContents.size();i++) {
				if(arrOfFileNames.get(i).contains("IDScheckpoint")) {
					allCheckPoints.add(arrOfFileNames.get(i));
				}
			}
			
			if(allCheckPoints.size()==0) {
				System.out.println("***First you need to create check point!!!");
			}
			else {
				String checkSelectionCP="";
				System.out.println("***Sensitive check points may lead redundant warnings, but more secured.");
				System.out.println("***Please select your check point.");
				for(int slctChckPnt=0;slctChckPnt<allCheckPoints.size();slctChckPnt++) {
					checkSelectionCP+="_"+slctChckPnt;
					System.out.println("->Enter "+slctChckPnt+" to use check point: "+allCheckPoints.get(slctChckPnt)+" .");
				}
				System.out.print("->Choice check point:");
				int selectionCP=scmdf.nextInt();
				if(checkSelectionCP.contains(selectionCP+"")) {
					String checkPointName=allCheckPoints.get(selectionCP);
					//checking whether checkpoint modified..
					boolean isCheckPointModified=false;
					String chckPntRaw="";
					for(int itr00=0;itr00<arrOfContents.size();itr00++) {
						if(arrOfFileNames.get(itr00).equals(checkPointName)) {
							String checkpntcntnt=arrOfContents.get(itr00);
							String chckpntdcrypt=aes.decrypt(checkpntcntnt, secretKeyIDS);
							String cp0=aes.decrypt(chckpntdcrypt, secretKeyIDS);
							cp0=aes.decrypt(cp0, secretKeyIDS);
							chckPntRaw=cp0;
							//System.out.println(cp0);
							if(cp0.equals("null")) {
								isCheckPointModified=true;
								System.out.println("***Check point: "+checkPointName+" modified!!!");
							}
							
						}
					}
					if(checkPointName.contains("sensitive") && !isCheckPointModified) {
						//System.out.println(chckPntRaw);
						
						String[] arrOfSplit = chckPntRaw.split(">cnr>");
						//System.out.println("--------------------------");
						ArrayList<String> FileNamesFromCP = new ArrayList<String>();
						ArrayList<String> FileContentsFromCP = new ArrayList<String>();
						int cntr=0;
						for (String a : arrOfSplit) {
							int sza=a.length();
							if(sza>=2 && !a.equals("") && !a.equals(System.lineSeparator())) {
								String cpya=a.substring(0, sza-2);
								if(cntr%2==0) {
									FileNamesFromCP.add(a);
								}
								else {
									FileContentsFromCP.add(a);
								}
								cntr+=1;
								//System.out.println(a);
							}
						}
						//System.out.println(FileNamesFromCP);
						//System.out.println(FileContentsFromCP);
						int modifiedFileCounter=0;
						for(int it=0;it<FileNamesFromCP.size();it++) {
							String CPfile=FileNamesFromCP.get(it);
							String CPContent=FileContentsFromCP.get(it);
							boolean isFileFound=false;
							for(int itt=0;itt<arrOfFileNameForLM.size();itt++) {
								if(arrOfFileNameForLM.get(itt).equals(CPfile)) {
									isFileFound=true;
									if(aes.encrypt(arrOfLastModified.get(itt), secretKeyIDS).equals(CPContent)) {
										
									}else {
										System.out.println("***Modified File: "+arrOfFileNameForLM.get(itt));
										modifiedFileCounter+=1;
									}
									
								}
							}
							if(!isFileFound) {
								System.out.println("***File: "+CPfile+" is not found(deleted)!!!");
							}
							
						}
						if(modifiedFileCounter==0) {
							System.out.println("***There is no modified file.");
						}
						
						
						
					}
					else if(!isCheckPointModified) {
						//System.out.println(chckPntRaw);
						String[] arrOfSplit = chckPntRaw.split(">cnr>");
						//System.out.println("--------------------------");
						ArrayList<String> FileNamesFromCP = new ArrayList<String>();
						ArrayList<String> FileContentsFromCP = new ArrayList<String>();
						int cntr=0;
						for (String a : arrOfSplit) {
							int sza=a.length();
							if(sza>=2 && !a.equals("") && !a.equals(System.lineSeparator())) {
								String cpya=a.substring(0, sza-2);
								if(cntr%2==0) {
									FileNamesFromCP.add(a);
								}
								else {
									FileContentsFromCP.add(a);
								}
								cntr+=1;
								//System.out.println(a);
							}
						}
						//System.out.println(FileNamesFromCP);
						//System.out.println(FileContentsFromCP);
						
						int modifiedFileCounter=0;
						for(int it=0;it<FileNamesFromCP.size();it++) {
							String CPfile=FileNamesFromCP.get(it);
							String CPContent=FileContentsFromCP.get(it);
							boolean isFileFound=false;
							for(int itt=0;itt<arrOfFileNames.size();itt++) {
								if(arrOfFileNames.get(itt).equals(CPfile)) {
									isFileFound=true;
									if(arrOfContents.get(itt).equals(CPContent)) {
										
									}else {
										System.out.println("***Modified File: "+arrOfFileNames.get(itt));
										modifiedFileCounter+=1;
									}
									
								}
							}
							if(!isFileFound) {
								System.out.println("***File: "+CPfile+" is not found(deleted)!!!");
							}
						}
						if(modifiedFileCounter==0) {
							System.out.println("***There is no modified file.");
						}
					}
				}
				else {
					System.out.println("***Choice of check point is wrong!!!");
				}
				
			}
			
			
			
			
			
		}catch(IOException e) {}
		
	}

	public static void main(String[] args) {
		System.out.println("Host IDS working...");
		System.out.println("Enter directory which IDS will work on it:");
		String dir=sc.next();
		boolean isDirOk=false;
		File file = new File(dir);
		if(file.isDirectory()) {
			isDirOk=true;
		}else {
			isDirOk=false;
			while(!isDirOk) {
				System.out.println("Directory does not exist!!!");
				System.out.println("Enter directory which IDS will work on it:");
				dir=sc.next();
				File file0 = new File(dir);
				if(file0.isDirectory()) {
					isDirOk=true;
				}
				else {
					isDirOk=false;
				}
				
			}
		}
		String secretKeyIDS="cnr";
		while(isDirOk) {
			int selection = 0;
			System.out.println("Please enter your choice:");
			System.out.println("->Enter 1 to see identical files on directory.");
			System.out.println("->Enter 2 to create checkpoint on directory.");
			System.out.println("->Enter 3 to see modified files in directory.");
			System.out.println("->Enter 4 to exit.");
			System.out.print("->Choice:");
			selection=sc.nextInt();
			if(selection==1) {
				printIdenticalFiles(dir,secretKeyIDS);
			}
			else if(selection==2) {
				createCheckPoint(dir,secretKeyIDS);
			}
			else if(selection==3) {
				printModifiedFiles(dir,secretKeyIDS);
			}
			else if(selection==4) {
				break;
			}
			else {
				System.out.println("Wrong selection!!!");
			}
		}
		
		
		
		
	}

}
















