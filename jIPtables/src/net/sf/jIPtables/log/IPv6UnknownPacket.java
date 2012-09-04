package net.sf.jIPtables.log;

import java.util.Arrays;

/**
 * An unknown IPv6 transport packet
 *
 */
public class IPv6UnknownPacket extends IPv6Packet {

	private byte[] header;

	protected void setRawHeader(byte[] header) {
		this.header = header;
	}

	public byte[] getHeader() {
		return header;
	}

	@Override
	public String toString() {
		return "IPv6UnknownPacket [header=" + Arrays.toString(header) + ", toString()=" + super.toString() + "]";
	}
}
