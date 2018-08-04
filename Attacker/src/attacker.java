import java.io.BufferedWriter;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.io.Writer;

import org.jnetpcap.Pcap;

public class attacker {

	public static void main(String[] args)  {


		String pcapPath = args[5];
		String outputFile = args[6];




		StringBuilder errbuf = new StringBuilder();
		final Pcap pcap = Pcap.openOffline(pcapPath,errbuf);
		//Throw exception if it cannot open the file
		if (pcap == null) {  
			try {
				throw new Exception(errbuf.toString());
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} 
		}

		//Next, we create a packet handler which will receive packets from the libpcap loop.
		PcapPacketHandler_Imp jpacketHandler = new PcapPacketHandler_Imp(); 
		jpacketHandler.initiate_Variables(args);
		pcap.loop(-1, jpacketHandler,"");
		pcap.close();  
		/*
		int sumBytes = 0 ;
		int sumPackets = 0 ;
		for (int i = 0; i < jpacketHandler.sumOfBytesPerWindow.length; i++) {
			System.out.println("Bit "+i+" :" +jpacketHandler.sumOfBytesPerWindow[i]+" :" +jpacketHandler.numPfPacketPerWindow[i]);
			sumBytes = sumBytes + jpacketHandler.sumOfBytesPerWindow[i];
			sumPackets = sumPackets + jpacketHandler.numPfPacketPerWindow[i];
		}
		System.out.println(sumBytes);
		System.out.println(sumPackets);
		*/ 
		int[] binMsgArr = jpacketHandler.binMsgArr;
		/*
		for(int i = 0; i < binMsgArr.length; i = i +8)
		{
			System.out.println(binMsgArr[i]+""+binMsgArr[i+1]+""+binMsgArr[i+2]+""+binMsgArr[i+3]+" "+binMsgArr[i+4]+""+binMsgArr[i+5]+""+binMsgArr[i+6]+""+binMsgArr[i+7]+"                     ["+(i)+":"+(i+7)+"]");
		
		}
		*/

		int[] decimalArray = binaryToDecimalArray(binMsgArr);
		String ans = "";
		for (int i = 0; i < decimalArray.length; i++) {
			/*
			System.out.println(decimalArray[i]+ ":"+ (char) decimalArray[i]+"                     ["+(i*8)+":"+(((i+1)*8)-1)+"]");
			*/
			ans = ans + (char) decimalArray[i];
		}
		
		
		try (Writer writer = new BufferedWriter(new OutputStreamWriter(
	              new FileOutputStream(outputFile), "utf-8"))) {
	   writer.write(ans);
	} catch (UnsupportedEncodingException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	} catch (FileNotFoundException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	} catch (IOException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}


	}


	private static int[] binaryToDecimalArray(int[] binArray){
		int[] DecimalArray = new int[binArray.length/8];
		int currentValue;
		for (int i = 0; i < DecimalArray.length; i++) {
			currentValue = 0;
			for (int j = 0; j < 8; j++) {
				currentValue += binArray[i*8 + j] * Math.pow(2, 7-j);
			}
			DecimalArray[i] = currentValue;
		}
		return DecimalArray;
	}

}