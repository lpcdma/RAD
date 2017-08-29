package org.ali;
import com.google.common.io.ByteStreams;
import java.io.File;
import java.io.FileInputStream;
import java.io.BufferedInputStream;
import org.jf.dexlib2.dexbacked.BaseDexBuffer;
import org.jf.dexlib2.dexbacked.DexBackedDexFile;
import java.util.Arrays;
public class demolishHelper{
	private static int[]maps=new int[65536];
	private static int start=0;
	private static byte[] addBuf;
	private static int fakeStart = 0;
	private static byte[] readFile(String fileName){
		try{
		FileInputStream inStream = new FileInputStream(fileName);
		int size=inStream.available();
		byte[] buf=new byte[size];
		inStream.read(buf);
		inStream.close();
		return buf;
		}catch(Exception e){}
		return new byte[0];
	}
	private static int getDexId(String className){
		int len=className.length();
		if(!className.substring(len-4,len).equals(".dex"))return 0;
		String a=className.substring(className.lastIndexOf("classes")+7,len-4);
		if(a.length()==0)return 0;
		return Integer.parseInt(a,10);
	}
	public static void readData(String className){
		byte[] buf=readFile("libdemolishdata.so");
		BaseDexBuffer reader=new BaseDexBuffer(buf);
		int dexId=getDexId(className);
		int multiDexId=reader.readSmallUint(4);
		start=0;
		while(multiDexId!=dexId){
			start+=reader.readSmallUint(8);
			reader=new BaseDexBuffer(buf,start);
			multiDexId=reader.readSmallUint(4);
		}
		int funcs=reader.readSmallUint(12);
		Arrays.fill(maps,0);
		for(int i=0;i<funcs;i++){
			maps[reader.readSmallUint(16+i*16+8)]=reader.readSmallUint(16+i*16+12);
		}
		addBuf=buf;
	}
	public static byte[] getAddBuf(){
		return addBuf;
	}
	public static int checkMethodFlags(int id,int flag){
		if(((flag&0x100)!=0x100)||(maps[id]==0))return flag;
		return flag-0x100;
	}
	public static retInfo checkMethodId(int id){
		retInfo ret=new retInfo();
		if(maps[id]==0)ret.fake=false;else{
			ret.fake=true;
			ret.codeOff=maps[id]+fakeStart;
		}
		return ret;
	}
	public static void revFake(int fakeStartP){
		fakeStart=fakeStartP+start;
	}
}