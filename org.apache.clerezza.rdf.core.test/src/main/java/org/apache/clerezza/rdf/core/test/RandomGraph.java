/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.clerezza.rdf.core.test;

import java.util.Iterator;
import java.util.UUID;
import org.apache.clerezza.rdf.core.BNode;
import org.apache.clerezza.rdf.core.MGraph;
import org.apache.clerezza.rdf.core.NonLiteral;
import org.apache.clerezza.rdf.core.Resource;
import org.apache.clerezza.rdf.core.Triple;
import org.apache.clerezza.rdf.core.UriRef;
import org.apache.clerezza.rdf.core.impl.PlainLiteralImpl;
import org.apache.clerezza.rdf.core.impl.TripleImpl;
import org.apache.commons.lang.RandomStringUtils;

/**
 * A <code>MGraph</code> wrapper that allows randomly growing and shrinking of
 * the wrapped mgraph.
 *
 * @author mir
 */
public class RandomGraph extends MGraphWrapper {
	private int growthSpeed = 3;
	private int interconnectivity = 2;

	public RandomGraph(MGraph mGraph) {
		super(mGraph);
	}

	public RandomGraph(int growthSpeed, int interconnectivity, MGraph mGraph) {
		super(mGraph);
		if (growthSpeed <= 0 || interconnectivity <= 0) {
			throw new IllegalArgumentException("growth speed and the interconnectivity "
					+ "value have to be equals or highter one");
		}
		this.growthSpeed = growthSpeed;
		this.interconnectivity = interconnectivity;
	}

	/**
	 * Add or removes randomly a triple.
	 *
	 * @return the triple that was added or removed.
	 */
	public Triple evolve() {
		Triple triple;
		int random = rollDice(growthSpeed);
		if (random == 0 && size() != 0) {
			triple = getRandomTriple();
			remove(triple);
		} else {
			triple = createRandomTriple();
			add(triple);
		}
		return triple;
	}
		
	private Triple createRandomTriple() {
		return new TripleImpl(getSubject(), getPredicate(), getObject());
	}

	private NonLiteral getSubject() {
		int random = rollDice(interconnectivity);
		System.out.println("---->" + random);
		if (size() == 0) {
			random = 0;
		}
		switch (random) {
			case 0: // create new NonLiteral
				Resource newResource;
				do {
					newResource = createRandomResource();
				} while (!(newResource instanceof NonLiteral));
				return (NonLiteral) newResource;
			default: // get existing NonLiteral
				Resource existingResource;
				do {
					existingResource = getExistingResource();
					if (existingResource == null) {
						random = 0;
					}
				} while (!(existingResource instanceof NonLiteral));

				return (NonLiteral) existingResource;
		}
	}

	private UriRef getPredicate() {
		int random = rollDice(interconnectivity);
		if (size() == 0) {
			random = 0;
		}
		switch (random) {
			case 0: // create new UriRef
				return createRandomUriRef();
			default: // get existing UriRef
				Resource existingResource;
				do {
					existingResource = getExistingResource();
					if (existingResource == null) {
						random = 0;
					}
				} while (!(existingResource instanceof UriRef));
				return (UriRef) existingResource;
		}
	}

	private Resource getObject() {
		int random = rollDice(interconnectivity);
		if (size() == 0) {
			random = 0;
		}		
		switch (random) {
			case 0: // create new resource
				return createRandomResource();
			default: // get existing resource
				Resource existingResource = getExistingResource();
				if (existingResource == null) {
					random = 0;
				}
				return existingResource;
		}
	}

	private static int rollDice(int faces) {
		return Double.valueOf(Math.random() * faces).intValue();
	}

	private Resource createRandomResource() {
		switch (rollDice(3)) {
			case 0:
				return new BNode();
			case 1:
				return createRandomUriRef();
			case 2:
				return new PlainLiteralImpl(RandomStringUtils.random(rollDice(100) + 1));
		}
		throw new RuntimeException("in createRandomResource()");
	}

	private Resource getExistingResource() {
		Triple triple = getRandomTriple();
		if (triple == null) {
			return null;
		}
		switch (rollDice(3)) {
			case 0:
				return triple.getSubject();
			case 1:
				return triple.getPredicate();
			case 2:
				return triple.getObject();
		}
		return null;
	}

	private UriRef createRandomUriRef() {
		return new UriRef("http://" + UUID.randomUUID().toString());
	}

	/**
	 * Returns a random triple.
	 */
	public Triple getRandomTriple() {
		int size = this.size();
		if (size == 0) {
			return null;
		}
		Iterator<Triple> triples = iterator();
		while (triples.hasNext()) {
			Triple triple = triples.next();
			if (rollDice(this.size()) == 0) {
				return triple;
			}
		}
		return getRandomTriple();
	}
}
