import java.math.BigDecimal;
import java.util.Arrays;

import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.lan.Ethernet;

public class PcapPacketHandler_Imp implements PcapPacketHandler<String> {
		int my_Index;
		BigDecimal start_Time;
		int numOfBits;
		BigDecimal window;
		int cutoff;
		byte[] MAC_ID_Byte_Arr;
		int[] binMsgArr;
		int[] sumOfBytesPerWindow;
		int sumOfBytes;
		int numPfPacket;
		int[] numPfPacketPerWindow;

		BigDecimal startWindow;
		BigDecimal endWindow;

		public void initiate_Variables(String[] args)
		{
			my_Index = 0;
			start_Time = new BigDecimal(args[0]);
			numOfBits = Integer.parseInt(args[1]);
			window = new BigDecimal(args[2]).divide(new BigDecimal(1000));			
			cutoff = Integer.parseInt(args[3]);
			String MAC_ID = args[4];
			String[] macAddressParts = MAC_ID.split(":");
			MAC_ID_Byte_Arr = new byte[6];
			for (int i = 0; i < MAC_ID_Byte_Arr.length; i++) 
			{
				Integer hex = Integer.parseInt(macAddressParts[i], 16);
				MAC_ID_Byte_Arr[i] = hex.byteValue();
			}
			startWindow = start_Time;
			endWindow = startWindow.add(window);	
			binMsgArr = new int[numOfBits];
			sumOfBytesPerWindow = new int[numOfBits];
			numPfPacketPerWindow = new int[numOfBits];
			sumOfBytes = 0;
			numPfPacket = 0;

		}


		@Override
		public void nextPacket(PcapPacket currentPacket, String PaketsList) 
		{  
			BigDecimal packetSendTime = new BigDecimal(currentPacket.getCaptureHeader().timestampInNanos()).divide(new BigDecimal(1000000000));
			if (my_Index >= numOfBits)
				return;
			if(packetSendTime.compareTo(endWindow) > 0)
			{
				double avg = sumOfBytes/window.intValue();
				
				if(avg > cutoff)
				{
					binMsgArr[my_Index] = 1;
				}
				sumOfBytesPerWindow[my_Index] = (int)avg;
				numPfPacketPerWindow[my_Index] = numPfPacket;
				my_Index = my_Index +1;
				startWindow = endWindow;
				endWindow = startWindow.add(window);
				sumOfBytes = 0;
				numPfPacket = 0;
			}
			if(packetSendTime.compareTo(startWindow) >= 0 && packetSendTime.compareTo(endWindow)<=0 )
			{
				Ethernet eth = new Ethernet();
				eth = currentPacket.getHeader(eth);
				byte[] desMacID = eth.destination();
				if(Arrays.equals(desMacID,MAC_ID_Byte_Arr))
				{
					//sumOfBytes = sumOfBytes + currentPacket.size();
					sumOfBytes = sumOfBytes + currentPacket.getTotalSize();
					numPfPacket = numPfPacket +1;
				}
			}
		}
		public int[] get_BinMsgArr()
		{
			return binMsgArr;
		}
		public int[] sumOfBytesPerWindow()
		{
			return sumOfBytesPerWindow;
		}
}
