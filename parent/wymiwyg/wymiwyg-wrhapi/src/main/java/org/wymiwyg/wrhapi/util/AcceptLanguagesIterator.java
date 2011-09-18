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
package org.wymiwyg.wrhapi.util;



import java.util.Iterator;
import java.util.SortedSet;
import java.util.TreeSet;


/**
 * @author reto
 */
public class AcceptLanguagesIterator implements Iterator<AcceptLanguageHeaderEntry> {

    private Iterator<AcceptLanguageHeaderEntry> iterator;

    /**
     * @param acceptHeaders the accept-headers as strings
     *
     */
    public AcceptLanguagesIterator(String[] acceptHeaders) {
        SortedSet<AcceptLanguageHeaderEntry> acceptHeaderSet = new TreeSet<AcceptLanguageHeaderEntry>();

        for (int i = 0; i < acceptHeaders.length; i++) {
            String currentstring = acceptHeaders[i];
            AcceptLanguageHeaderEntry currentHeader = new AcceptLanguageHeaderEntry(currentstring);
            acceptHeaderSet.add(currentHeader);
        }

        iterator = acceptHeaderSet.iterator();
    }

    /**
     * @see java.util.Iterator#hasNext()
     */
    public boolean hasNext() {
        return iterator.hasNext();
    }

    /**
     * @see java.util.Iterator#next()
     */
    public AcceptLanguageHeaderEntry next() {
        return nextAcceptLanguageHeader();
    }

    /**
     * @return
     */
    public AcceptLanguageHeaderEntry nextAcceptLanguageHeader() {
        return (AcceptLanguageHeaderEntry) iterator.next();
    }

    /**
     * @see java.util.Iterator#remove()
     */
    public void remove() {
        iterator.remove();
    }
}
