package net.sf.jIPtables.rules;

import static org.junit.Assert.*;
import java.util.Iterator;
import java.util.regex.Matcher;
import net.sf.jIPtables.rules.Chain.Policy;
import org.junit.Test;

public class ChainTest {

	@Test
	public void testGetCommand() {
		Chain c = buildTestChain("test");
		Matcher m = Chain.chainPattern.matcher(c.getCommand());
		assertTrue(m.find());
	}

	private Chain buildTestChain(String name) {
		return new Chain(name);
	}

	@Test
	public void testAddRule() {
		Chain c = buildTestChain("test");
		Rule r = Rule.buildFromCommand("-A test -m state -j ACCEPT --state RELATED,ESTABLISHED");
		c.addRule(r);
		assertTrue(c.getRules().contains(r));
	}

	@Test
	public void testGetRules() {
		Chain c = buildTestChain("test");
		Rule r = Rule.buildFromCommand("-A test -m state -j ACCEPT --state RELATED,ESTABLISHED");
		c.addRule(r);
		assertTrue(c.getRules().contains(r));
		c.getRules().remove(r);
		assertTrue(c.getRules().contains(r));
	}

	@Test
	public void testSetPacketsNum() {
		Chain c = buildTestChain("test");
		c.setPacketsNum(200);
		assertTrue(c.getPacketsNum() == 200);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testNegativePacketsNum() {
		Chain c = buildTestChain("test");
		c.setPacketsNum(-200);
	}

	@Test
	public void testSetBytesNum() {
		Chain c = buildTestChain("test");
		c.setBytesNum(200);
		assertTrue(c.getBytesNum() == 200);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testNegativeBytesNum() {
		Chain c = buildTestChain("test");
		c.setBytesNum(-200);
	}

	@Test
	public void testGetName() {
		Chain c = buildTestChain("test");
		assertTrue("test".equals(c.getName()));
	}

	@Test
	public void testSetDefaultPolicy() {
		Chain c = buildTestChain("Test");
		c.setDefaultPolicy(Policy.REJECT);
		assertTrue(c.getDefaultPolicy().equals(Policy.REJECT));
		assertFalse(c.getDefaultPolicy().equals(Policy.DROP));
	}

	@Test
	public void testClone() {
		Chain c = buildTestChain("test");
		Chain clone = c.clone();
		assertFalse(c == clone);
		assertTrue(c.equals(clone));
	}

	@Test
	public void testIterator() {
		Chain c = buildTestChain("test");
		Rule r = Rule.buildFromCommand("-A test -m state -j ACCEPT --state RELATED,ESTABLISHED");
		c.addRule(r);
		Iterator<Rule> i = c.iterator();
		assertEquals(r, i.next());
	}

}
