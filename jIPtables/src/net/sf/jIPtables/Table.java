/**
 * @package		jIPtables
 * @copyright	Copyright (C) 2011 IPTables Java LIbrary. All rights reserved.
 * @license		GNU/GPL, see COPYING file
 * @author		Daniel Zozin
 *
 * This file is part of IPTables Java LIbrary.
 * IPTables Java LIbrary is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * IPTables Java LIbrary is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with IPTables Java LIbrary.  If not, see <http://www.gnu.org/licenses/>.
 *
 */
package net.sf.jIPtables;

import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import net.sf.jIPtables.Chain;

/**
 * A table that contain chains
 * 
 */
public class Table {
	
	private String name;
	
	public Table(String name) {
		this.name = name;
	}
	
	public String getName() {
		return name;
	}

	/**
	 * The chain associated with this table
	 */
	protected Map<String, Chain> chains = new HashMap<String, Chain>();

	/**
	 * Get the chains associated with this table
	 */
	public Collection<Chain> getChains() {
		return Collections.unmodifiableCollection(chains.values());
	}

	/**
	 * Get the specified chain, returns null if the chain doesn't exist
	 */
	public Chain getChain(String chainName) {
		if (chainName == null)
			throw new NullPointerException();
		return chains.get(chainName);
	}

	/**
	 * Add the specified chain to this table
	 */
	public void addChain(Chain chain) {
		if(chain == null)
			throw new NullPointerException();
		if (!chains.containsKey(chain))
			chains.put(chain.getName(), chain);
	}

	/**
	 * Get the iptables to import the table
	 * 
	 * @return The iptables command
	 */
	public String getCommand() {
		if(chains.isEmpty())
			return "";
		StringBuilder out = new StringBuilder("*"+name+"\n");
		for (Chain c : chains.values()) {
			out.append(c.getCommand() + "\n");
		}
		return out.toString();
	}

	@Override
	public String toString() {
		StringBuilder out = new StringBuilder(name + " table:\n");
		for (Chain c : chains.values()) {
			out.append(c.toString() + "\n");
		}
		return out.toString();
	}
}