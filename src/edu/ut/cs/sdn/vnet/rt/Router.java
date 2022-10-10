package edu.ut.cs.sdn.vnet.rt;

import edu.ut.cs.sdn.vnet.Device;
import edu.ut.cs.sdn.vnet.DumpFile;
import edu.ut.cs.sdn.vnet.Iface;

import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPacket;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.MACAddress;

/**
 * @author Aaron Gember-Jacobson and Anubhavnidhi Abhashkumar
 */
public class Router extends Device
{	
	/** Routing table for the router */
	private RouteTable routeTable;
	
	/** ARP cache for the router */
	private ArpCache arpCache;
	
	/**
	 * Creates a router for a specific host.
	 * @param host hostname for the router
	 */
	public Router(String host, DumpFile logfile)
	{
		super(host,logfile);
		this.routeTable = new RouteTable();
		this.arpCache = new ArpCache();
	}
	
	/**
	 * @return routing table for the router
	 */
	public RouteTable getRouteTable()
	{ return this.routeTable; }
	
	/**
	 * Load a new routing table from a file.
	 * @param routeTableFile the name of the file containing the routing table
	 */
	public void loadRouteTable(String routeTableFile)
	{
		if (!routeTable.load(routeTableFile, this))
		{
			System.err.println("Error setting up routing table from file "
					+ routeTableFile);
			System.exit(1);
		}
		
		System.out.println("Loaded static route table");
		System.out.println("-------------------------------------------------");
		System.out.print(this.routeTable.toString());
		System.out.println("-------------------------------------------------");
	}
	
	/**
	 * Load a new ARP cache from a file.
	 * @param arpCacheFile the name of the file containing the ARP cache
	 */
	public void loadArpCache(String arpCacheFile)
	{
		if (!arpCache.load(arpCacheFile))
		{
			System.err.println("Error setting up ARP cache from file "
					+ arpCacheFile);
			System.exit(1);
		}
		
		System.out.println("Loaded static ARP cache");
		System.out.println("----------------------------------");
		System.out.print(this.arpCache.toString());
		System.out.println("----------------------------------");
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
		
		/********************************************************************/
		/* TODO: Handle packets                                             */
		// IPv4 Check
		if (Ethernet.TYPE_IPv4 != etherPacket.getEtherType()) {
			System.out.println("Packet is not IPv4");
			return;
		}

		// Verify Checksum
		IPv4 packetHeader = (IPv4) etherPacket.getPayload();
		short checkSum = packetHeader.getChecksum();
		packetHeader.resetChecksum();
		byte[] serializedHeader = packetHeader.serialize();
		packetHeader = (IPv4) packetHeader.deserialize(serializedHeader, 0, serializedHeader.length);
		short newCheckSum = packetHeader.getChecksum();
		if (checkSum != newCheckSum) {
			System.out.println("Checksum verification failed");
			return;
		}
		// Check Ttl
		byte oldTtl = packetHeader.getTtl();
		packetHeader.setTtl(--oldTtl);
		if (0 == packetHeader.getTtl()) {
			System.out.println("Ttl == 0");
			return;
		}

		// put the new checksum into the header
		packetHeader.resetChecksum();
		serializedHeader = packetHeader.serialize();
		packetHeader = (IPv4) packetHeader.deserialize(serializedHeader, 0, serializedHeader.length);
		newCheckSum = packetHeader.getChecksum();
		packetHeader.setChecksum(newCheckSum);
		etherPacket.setPayload((IPacket) packetHeader);

		// Check interfaces
		int dstAddress = packetHeader.getDestinationAddress();
		for (Iface iFace : interfaces.values()) {
			if (dstAddress == iFace.getIpAddress()) {
				return;
			}
		}
		// Forward
		RouteEntry entry = routeTable.lookup(dstAddress);
		if (entry == null) {
			System.out.println("Couldn't find address in route table");
			return;
		}
		// Update MACs for packet
		int nextHopAddr = entry.getGatewayAddress() != 0 ? entry.getGatewayAddress() : dstAddress;
		ArpEntry arpEntry = arpCache.lookup(nextHopAddr);
		if (arpEntry == null) {
			System.out.println("Couldnt find arp entry");
			return;
		}
		MACAddress arpMAC = arpEntry.getMac();
		etherPacket = etherPacket.setDestinationMACAddress(arpMAC.toBytes());
		Iface entryInterface = entry.getInterface();
		MACAddress iFaceMAC = entryInterface.getMacAddress();
		etherPacket = etherPacket.setSourceMACAddress(iFaceMAC.toBytes());
		if (!entryInterface.equals(inIface)){
			sendPacket(etherPacket, entryInterface);
		}

		/********************************************************************/
	}
}