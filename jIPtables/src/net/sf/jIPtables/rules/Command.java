/**
 * @package jIPtables
 * @copyright Copyright (C) 2011 IPTables Java LIbrary. All rights reserved.
 * @license GNU/GPL, see COPYING file
 * @author Daniel Zozin <zdenial@gmx.com>
 * 
 *         This file is part of IPTables Java LIbrary.
 *         IPTables Java LIbrary is free software: you can redistribute it
 *         and/or modify
 *         it under the terms of the GNU General Public License as published by
 *         the Free Software Foundation, either version 3 of the License, or
 *         (at your option) any later version.
 *         IPTables Java LIbrary is distributed in the hope that it will be
 *         useful,
 *         but WITHOUT ANY WARRANTY; without even the implied warranty of
 *         MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *         GNU General Public License for more details.
 * 
 *         You should have received a copy of the GNU General Public License
 *         along with IPTables Java LIbrary. If not, see
 *         <http://www.gnu.org/licenses/>.
 * 
 */

package net.sf.jIPtables.rules;

import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

/**
 * The classes that extend this class can access iptables rules arguments
 * 
 */
public abstract class Command {

	/**
	 * The options of the command
	 */
	private final Map<String, String> options = new LinkedHashMap<String, String>();
	/**
	 * The options sets as negated
	 */
	private final Set<String> negatedOptions = new HashSet<String>();

	/**
	 * @return The commands for import in iptables
	 */
	public String getCommand() {
		StringBuilder out = new StringBuilder();
		for (Entry<String, String> entry : options.entrySet()) {
			String option = entry.getKey();
			out.append(negOp(option));
			out.append(' ');
			out.append(option);
			out.append(' ');
			out.append(entry.getValue());
		}
		return out.toString();
	}

	/**
	 * Set and option and return the old value
	 * 
	 * @param option
	 *            The option name
	 * @param value
	 *            The option value
	 * @return The old value
	 * @throws NullPointerException
	 *             If the passed option or value is null
	 */
	public String setOption(String option, String value) {
		if (option == null || value == null)
			throw new NullPointerException();
		String old = options.put(option, value);
		if (old == null)
			return "";
		return old;
	}

	/**
	 * Set and option and his negation status, return the old value
	 * 
	 * @param option
	 *            The option name
	 * @param value
	 *            The option value
	 * @param isNegated
	 *            The negation status, true means the option is negated
	 * @return The old value
	 * @throws NullPointerException
	 *             If the passed option or value is null
	 */
	public String setOption(String option, String value,boolean isNegated) {
		setNegated(option, isNegated);
		return setOption(option, value);
	}

	/**
	 * Unset the specified option and return the old value
	 * 
	 * @return The old value
	 * @throws NullPointerException
	 *             If the passed option is null
	 */
	public String unsetOption(String option) {
		if (option == null)
			throw new NullPointerException();
		String old = options.remove(option);
		if (old == null)
			return "";
		return old;
	}

	/**
	 * Check if an option is setted
	 * 
	 * @return True if the option is setted
	 * @throws NullPointerException
	 *             if the passed option is null
	 */
	public boolean isOptionSetted(String option) {
		if (option == null)
			throw new NullPointerException();
		return options.containsKey(option);
	}

	/**
	 * Get the value of the specified option, returns empty string if the
	 * specified option is not setted
	 * 
	 * @throws NullPointerException
	 *             If the passed option is null
	 */
	public String getOption(String option) {
		if (option == null)
			throw new NullPointerException();
		String o = options.get(option);
		if (o == null)
			return "";
		return o;
	}

	/**
	 * @return The map of the options
	 */
	public Map<String, String> getOptions() {
		return Collections.unmodifiableMap(options);
	}

	/**
	 * Set an option as negated with the negated operator ( ! option )
	 * 
	 * @param option
	 *            The option to negate
	 * @param isNegated
	 *            The negation status of the option, the default is false. To
	 *            negate the option set isNegated to true.
	 * @throws NullPointerException
	 *             If the passed option is null
	 */
	public void setNegated(String option, boolean isNegated) {
		if (option == null)
			throw new NullPointerException();
		if (isNegated)
			negatedOptions.add(option);
		else
			negatedOptions.remove(option);
	}

	/**
	 * 
	 * @return True if the specified option is set as negated
	 * @throws NullPointerException
	 *             If the passed option is null
	 */
	public boolean isNegated(String option) {
		if (option == null)
			throw new NullPointerException();
		return negatedOptions.contains(option);
	}

	/**
	 * @return The set of negated options
	 */
	public Set<String> getNegatedOptions() {
		return Collections.unmodifiableSet(negatedOptions);
	}

	/**
	 * Convenience method to add the negated operator in output if an option is
	 * negated
	 * 
	 * @return The " !" string if the option is negated, empty string otherwise
	 * @throws NullPointerException
	 *             If the passed option is null
	 */
	protected String negOp(String option) {
		if (option == null)
			throw new NullPointerException();
		return isNegated(option) ? " !" : "";
	}

	@Override
	public String toString() {
		StringBuilder out = new StringBuilder();

		for (Entry<String, String> e : getOptions().entrySet()) {
			out.append(e.getKey());

			String value = e.getValue();
			out.append('=' + value + ", ");
		}

		if (out.length() > 2)
			out.delete(out.length() - 2, out.length());

		Iterator<String> i = getNegatedOptions().iterator();

		if (!i.hasNext())
			return out.toString();

		out.append(", Neg(" + i.next());

		while (i.hasNext())
			out.append(',' + i.next());

		out.append(')');
		return out.toString();
	}
}
