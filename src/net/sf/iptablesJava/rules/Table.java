/**
 * @package iptables-java
 * @copyright Copyright (C) 2011 iptables-java. All rights reserved.
 * @license GNU/GPL, see COPYING file
 * @author "Daniel Zozin <zdenial@gmx.com>"
 * 
 *         This file is part of iptables-java.
 *         iptables-java is free software: you can redistribute it
 *         and/or modify
 *         it under the terms of the GNU General Public License as published by
 *         the Free Software Foundation, either version 3 of the License, or
 *         (at your option) any later version.
 *         iptables-java is distributed in the hope that it will be
 *         useful,
 *         but WITHOUT ANY WARRANTY; without even the implied warranty of
 *         MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *         GNU General Public License for more details.
 * 
 *         You should have received a copy of the GNU General Public License
 *         along with iptables-java. If not, see
 *         <http://www.gnu.org/licenses/>.
 * 
 */

package net.sf.iptablesJava.rules;

import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

/**
 * A table that contain chains
 * 
 */
public class Table implements Iterable<Chain> {

	private final String name;

	/**
	 * The chain associated with this table
	 */
	protected Map<String, Chain> chains = new HashMap<String, Chain>();

	/**
	 * Create a new table
	 * 
	 * @param name
	 *            The name of the table
	 * @throws IllegalArgumentException
	 *             If the passed name is null or is empty
	 */
	public Table(String name) {
		if (name == null || name.isEmpty())
			throw new IllegalArgumentException("Invalid table name");
		this.name = name;
	}

	/**
	 * @return The table name
	 */
	public String getName() {
		return name;
	}

	/**
	 * @return The chains associated with this table
	 */
	public Collection<Chain> getChains() {
		return Collections.unmodifiableCollection(chains.values());
	}

	/**
	 * @return The specified chain, returns null if the chain doesn't exist
	 * 
	 * @throws NullPointerException
	 *             If the passed name is null
	 */
	public Chain getChain(String chainName) {
		if (chainName == null)
			throw new NullPointerException();
		return chains.get(chainName);
	}

	/**
	 * Add the specified chain to this table
	 * 
	 * @throws NullPointerException
	 *             If the passed chain is null
	 */
	public void addChain(Chain chain) {
		if (chain == null)
			throw new NullPointerException();
		if (!chains.containsKey(chain))
			chains.put(chain.getName(), chain);
	}

	/**
	 * @return The corresponding iptables command
	 * 
	 */
	public String getCommand() {
		if (chains.isEmpty())
			return "";
		StringBuilder out = new StringBuilder("*" + name + "\n");
		for (Chain c : this)
			out.append(c.getCommand() + "\n");
		return out.toString();
	}

	@Override
	public String toString() {
		StringBuilder out = new StringBuilder(name + " table:\n");
		for (Chain c : chains.values())
			out.append(c.toString() + "\n");
		return out.toString();
	}

	@Override
	public Iterator<Chain> iterator() {
		return chains.values().iterator();
	}
}