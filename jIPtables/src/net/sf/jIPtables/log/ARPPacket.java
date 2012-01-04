package net.sf.jIPtables.log;

import java.net.InetAddress;

/**
 * An ARP packet logged by the firewall
 */
public class ARPPacket extends IPv4Packet {

	private int opcode;
	private InetAddress src;
	private InetAddress dst;
	private String HWsrc;
	private String HWdst;

	@Override
	protected void setField(String field, String value) {
		super.setField(field, value);
		if ("opcode".equals(field))
			opcode = Integer.parseInt(value);
		else if ("arp_src".equals(field))
			src = parseAddress(value);
		else if ("arp_dst".equals(field))
			src = parseAddress(value);
		else if ("arp_hwsrc".equals(field))
			HWsrc= value;
		else if ("arp_hwdst".equals(field))
			HWdst= value;
	}

	/**
	 * @return The ARP opcode
	 */
	public int getOpcode() {
		return opcode;
	}
	
	/**
	 * @return The ARP source IP address
	 */
	public InetAddress getARPSourceAddress() {
		return src;
	}
	
	/**
	 * @return The ARP destination IP address
	 */
	public InetAddress getARPDestinationAddress() {
		return dst;
	}
	
	/**
	 * @return The ARP source hardware address
	 */
	public String getARPHWSourceAddress() {
		return HWsrc;
	}
	
	/**
	 * @return The ARP destination hardware address
	 */
	public String getARPHWDestinationAddress() {
		return HWdst;
	}
}
