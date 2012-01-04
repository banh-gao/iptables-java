package net.sf.jIPtables;
import java.util.Map.Entry;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import net.sf.jIPtables.Chain.Policy;
import net.sf.jIPtables.RuleSet.TableType;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

public class XMLRules {
	public static Document getXml(RuleSet rules) {
		try {
			Document doc = DocumentBuilderFactory.newInstance()
					.newDocumentBuilder().newDocument();

			Element root = doc.createElement("ruleset");
			doc.appendChild(root);

			for (Table t : rules.getTables()) {
				root.appendChild(xmlTable(t, doc));
			}

			return doc;
		} catch (ParserConfigurationException e) {
			throw new RuntimeException(e);
		}
	}

	private static Element xmlTable(Table t, Document doc) {
		Element tableTag = doc.createElement("table");
		tableTag.setAttribute("name", t.getName());

		for (Chain c : t.getChains()) {
			tableTag.appendChild(xmlChain(c, doc));
		}

		return tableTag;
	}

	private static Element xmlChain(Chain chain, Document doc) {
		Element chainTag = doc.createElement("chain");
		chainTag.setAttribute("name", chain.getName());
		chainTag.setAttribute("policy", chain.getDefaultPolicy().toString());
		chainTag.setAttribute("packets", Long.toString(chain.getPacketsNum()));
		chainTag.setAttribute("bytes", Long.toString(chain.getBytesNum()));

		for (Rule r : chain.getRules()) {
			chainTag.appendChild(xmlRule(r, doc));
		}

		return chainTag;
	}

	private static Element xmlRule(Rule rule, Document doc) {
		Element ruleTag = doc.createElement("rule");

		ruleTag.setAttribute("packets", Long.toString(rule.getPacketsNum()));
		ruleTag.setAttribute("bytes", Long.toString(rule.getBytesNum()));

		for (Entry<String, String> e : rule.getOptions().entrySet()) {
			ruleTag.appendChild(xmlOption(e.getKey(), e.getValue(),
					rule.isNegated(e.getKey()), doc));
		}

		return ruleTag;
	}

	private static Element xmlOption(String name, String value,
			boolean isNegated, Document doc) {
		Element option = doc.createElement("option");
		option.setAttribute("name", name);
		option.setAttribute("isNegated", isNegated ? "true" : "false");
		option.appendChild(doc.createTextNode(value));
		return option;
	}

	public static RuleSet parseXml(Document doc) throws ParsingException {
		Element root = doc.getDocumentElement();
		if (!"ruleset".equals(root.getNodeName()))
			throw new ParsingException(
					"Invalid ruleset, the document element should be a ruleset tag");

		RuleSet ruleset = new RuleSet();

		NodeList tables = root.getChildNodes();
		for (int i = 0; i < tables.getLength(); i++) {
			if (!(tables.item(i) instanceof Element))
				continue;

			Element tElem = (Element) tables.item(i);

			if ("table".equals(tElem.getNodeName())) {
				parseTable(tElem, ruleset);
			}
		}
		return ruleset;
	}

	private static void parseTable(Element tableElement, RuleSet ruleset)
			throws ParsingException {
		try {
			TableType type = TableType.getType(tableElement
					.getAttribute("name"));

			Table table = ruleset.getTable(type);

			NodeList chains = tableElement.getChildNodes();
			for (int i = 0; i < chains.getLength(); i++) {
				if (!(chains.item(i) instanceof Element))
					continue;

				Element cElem = (Element) chains.item(i);

				if ("chain".equals(cElem.getNodeName()))
					table.addChain(parseChain(cElem));
			}
		} catch (IllegalArgumentException _) {
			throw new ParsingException("Invalid table type "
					+ tableElement.getAttribute("name"));
		}
	}

	private static Chain parseChain(Element chainElement)
			throws ParsingException {
		String chainName = chainElement.getAttribute("name");
		if (chainName.isEmpty())
			throw new ParsingException("Invalid chain name " + chainName);

		Chain chain = new Chain(chainName);
		try {
			long packets = Long.parseLong(chainElement.getAttribute("packets"));
			if (packets < 0)
				throw new NumberFormatException();
			chain.setPacketsNum(packets);
		} catch (NumberFormatException _) {
			throw new ParsingException("Invalid packets number "
					+ chainElement.getAttribute("packets"));
		}
		try {
			long bytes = Long.parseLong(chainElement.getAttribute("bytes"));
			if (bytes < 0)
				throw new NumberFormatException();
			chain.setBytesNum(bytes);
		} catch (NumberFormatException _) {
			throw new ParsingException("Invalid bytes number "
					+ chainElement.getAttribute("bytes"));
		}
		try {
			chain.setDefaultPolicy(Policy.valueOf(chainElement
					.getAttribute("policy")));
		} catch (IllegalArgumentException _) {
			throw new ParsingException("Invalid policy "
					+ chainElement.getAttribute("policy"));
		}

		NodeList rules = chainElement.getChildNodes();
		for (int i = 0; i < rules.getLength(); i++) {
			if (!(rules.item(i) instanceof Element))
				continue;

			Element rElem = (Element) rules.item(i);

			if ("rule".equals(rElem.getNodeName()))
				chain.addRule(parseRule(rElem));
		}
		return chain;
	}

	private static Rule parseRule(Element ruleElement) throws ParsingException {
		Rule rule = new Rule();
		try {
			long packets = Long.parseLong(ruleElement.getAttribute("packets"));
			if (packets < 0)
				throw new NumberFormatException();
			rule.setPacketsNum(packets);
		} catch (NumberFormatException _) {
			throw new ParsingException("Invalid packets number "
					+ ruleElement.getAttribute("packets"));
		}
		try {
			long bytes = Long.parseLong(ruleElement.getAttribute("bytes"));
			if (bytes < 0)
				throw new NumberFormatException();
			rule.setBytesNum(bytes);
		} catch (NumberFormatException _) {
			throw new ParsingException("Invalid bytes number "
					+ ruleElement.getAttribute("bytes"));
		}

		NodeList options = ruleElement.getChildNodes();
		for (int i = 0; i < options.getLength(); i++) {
			if (!(options.item(i) instanceof Element))
				continue;

			Element oElem = (Element) options.item(i);

			if ("option".equals(oElem.getNodeName()))
				parseOption(rule, oElem);
		}
		return rule;
	}

	private static void parseOption(Rule rule, Element optionElement)
			throws ParsingException {
		String name = optionElement.getAttribute("name");
		if (name.isEmpty()) {
			throw new ParsingException("Invalid option name");
		}
		boolean isNegated = ("true".equals(optionElement
				.getAttribute("isNegated")));
		String value = optionElement.getFirstChild().getNodeValue();
		rule.setOption(name, value);
		rule.setNegated(name, isNegated);
	}
}
