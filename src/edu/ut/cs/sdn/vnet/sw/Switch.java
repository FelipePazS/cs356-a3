package edu.ut.cs.sdn.vnet.sw;

import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.MACAddress;
import edu.ut.cs.sdn.vnet.Device;
import edu.ut.cs.sdn.vnet.DumpFile;
import edu.ut.cs.sdn.vnet.Iface;
import java.util.*;

/**
 * @author Aaron Gember-Jacobson
 */
public class Switch extends Device
{	
	/**
	 * Creates a router for a specific host.
	 * @param host hostname for the router
	 */

	Table table;

	public Switch(String host, DumpFile logfile)
	{
		super(host,logfile);
		table = new Table();
	}

	/**
	 * Handle an Ethernet packet received on a specific interface.
	 * @param etherPacket the Ethernet packet that was received
	 * @param inIface the interface on which the packet was received
	 */
	public void handlePacket(Ethernet etherPacket, Iface inIface)
	{
		System.out.println("*** -> Received packet: " +
                etherPacket.toString().replace("\n", "\n\t"));

		MACAddress dst_mac = etherPacket.getDestinationMAC();
		MACAddress src_mac = etherPacket.getSourceMAC(); 
		table.sweep();
		table.update_entries(src_mac, inIface);

		if (table.has_entry(dst_mac)){
			BridgeEntry b = table.get_entry(dst_mac);
			sendPacket(etherPacket, b.iface);
		}
		else {
			// broadcast
			for (String interface_string : interfaces.keySet()){
				if(!interfaces.get(interface_string).toString().equals(inIface.toString())){
					sendPacket(etherPacket, interfaces.get(interface_string));
				}
			}
		}
	}
}

class BridgeEntry {
	public MACAddress MacAddr; // destination
	public Iface iface; // interface to send the package to
	public int update_time;

	public BridgeEntry(MACAddress _MacAddr,Iface _interface){
		MacAddr = _MacAddr;
		iface = _interface;
		update_time = ((int) System.currentTimeMillis() / 1000);
	}
}

class Table {
	BridgeEntry[] entries;

	public Table(){
		entries = new BridgeEntry[0];
	}

	public boolean has_entry(MACAddress dest){
		for (int i = 0; i < entries.length; i ++){
			BridgeEntry b = entries[i];
			if (b.MacAddr.equals(dest)){
				return true;
			}
		}
		return false;
	}

	public void update_entries(MACAddress MAC, Iface _interface){
		BridgeEntry b;
		for (int i = 0; i < entries.length; i ++){
			b = entries[i];
			if (b.MacAddr.equals(MAC)){
				// found the entry with this mac address
				b.iface = _interface;
				b.update_time = ((int) System.currentTimeMillis() / 1000);
				return;
			}
		}
		// didn't found entry in the table, append the new one
		BridgeEntry entry = new BridgeEntry(MAC, _interface);
		BridgeEntry[] temp = Arrays.copyOf(entries, entries.length + 1);
		temp[temp.length - 1] = entry;
		entries = Arrays.copyOf(temp, temp.length);
	}

	public BridgeEntry get_entry(MACAddress MAC){
		BridgeEntry b = null;
		for (int i = 0; i < entries.length; i ++){
			b = entries[i];
			if (b.MacAddr.equals(MAC)){
				return b;
			}
		}
		return b;
	}

	public void sweep(){
		Boolean done = false;
		int i = 0;
		while(!done){
			if (i < entries.length){
				BridgeEntry b = entries[i];
				if ((((int) System.currentTimeMillis() / 1000) - b.update_time) > 15){
					remove_element(i);
				}
			}
			else {
				done = true;
			}
			i ++;
		}
	}

	public void remove_element(int indx){
		BridgeEntry[] temp = new BridgeEntry[entries.length - 1];
		int i = 0;
		int x = 0;
		while (i < temp.length){
			if (x == indx){
				x++;
			}
			temp[i] = entries[x];
			x++;
			i ++;
		}
		entries = Arrays.copyOf(temp, temp.length);
	}

}