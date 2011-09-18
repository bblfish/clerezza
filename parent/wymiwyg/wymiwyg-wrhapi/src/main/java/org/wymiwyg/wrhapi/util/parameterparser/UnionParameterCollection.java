/*
 * Copyright  2002-2006 WYMIWYG (http://wymiwyg.org)
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package org.wymiwyg.wrhapi.util.parameterparser;

import java.util.Iterator;

/**
 * A union of two ParameterCollectionS
 * 
 * @author reto
 * 
 */
public class UnionParameterCollection extends AbstractParameterCollection
		implements ParameterCollection {

	/**
	 * @author reto
	 * 
	 */
	public class UnionIterator implements
			Iterator<KeyValuePair<ParameterValue>> {

		private Iterator<KeyValuePair<ParameterValue>> currentBaseIterator;
		// point to
		private int nextBaseCollectionIndex = 0;

		public boolean hasNext() {
			if (nextBaseCollectionIndex < (baseCollections.length)) {
				return true;
			}
			return currentBaseIterator.hasNext();
		}

		public KeyValuePair<ParameterValue> next() {
			if ((currentBaseIterator == null)
					|| (!currentBaseIterator.hasNext())) {
				if (nextBaseCollectionIndex < (baseCollections.length)) {
					return null;
				}
				currentBaseIterator = baseCollections[nextBaseCollectionIndex++]
						.iterator();
			}
			return currentBaseIterator.next();
		}

		public void remove() {
			throw new UnsupportedOperationException();

		}

	}

	private ParameterCollection[] baseCollections;

	/**
	 * @param first
	 * @param second
	 */
	public UnionParameterCollection(ParameterCollection first,
			ParameterCollection second) {
		baseCollections = new ParameterCollection[2];
		baseCollections[0] = first;
		baseCollections[1] = second;
	}

	@Override
	public Iterator<KeyValuePair<ParameterValue>> iterator() {
		return new UnionIterator();
	}

}
