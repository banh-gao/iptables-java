package net.sf.iptablesJava.log;

import java.net.InetAddress;

public class IGMPPacket extends IPv4Packet {

	private int type;
	private int code;
	private InetAddress group;

	@Override
	protected void setField(String field, String value) {
		super.setField(field, value);
		if ("type".equals(field))
			type = Integer.parseInt(value);
		else if ("code".equals(field))
			code = Integer.parseInt(value);
		else if ("group".equals(field))
			group = parseAddress(value);
	}

	public int getType() {
		return type;
	}

	public int getCode() {
		return code;
	}

	public InetAddress getGroup() {
		return group;
	}

	@Override
	public String toString() {
		return "IGMPPacket [type=" + type + ", code=" + code + ", group="
				+ group + ", toString()=" + super.toString() + "]";
	}
}
