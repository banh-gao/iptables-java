package net.sf.iptablesJava.log;

import java.util.Arrays;

/**
 * An unknown IPv4 transport packet
 *
 */
public class IPv4UnknownPacket extends IPv4Packet {

	private byte[] header;

	protected void setRawHeader(byte[] header) {
		this.header = header;
	}

	public byte[] getHeader() {
		return header;
	}

	@Override
	public String toString() {
		return "IPv4UnknownPacket [header=" + Arrays.toString(header) + ", toString()=" + super.toString() + "]";
	}
}
