/**
 * @package jIPtables
 * @copyright Copyright (C) 2011 jIPtables. All rights reserved.
 * @license GNU/GPL, see COPYING file
 * @author "Daniel Zozin <zdenial@gmx.com>"
 * 
 *         This file is part of jIPtables.
 *         jIPtables is free software: you can redistribute it
 *         and/or modify
 *         it under the terms of the GNU General Public License as published by
 *         the Free Software Foundation, either version 3 of the License, or
 *         (at your option) any later version.
 *         jIPtables is distributed in the hope that it will be
 *         useful,
 *         but WITHOUT ANY WARRANTY; without even the implied warranty of
 *         MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *         GNU General Public License for more details.
 * 
 *         You should have received a copy of the GNU General Public License
 *         along with jIPtables. If not, see
 *         <http://www.gnu.org/licenses/>.
 * 
 */

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
