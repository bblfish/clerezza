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
package org.apache.clerezza.platform.xhtml2html;

import java.util.ArrayList;
import java.util.List;
import org.wymiwyg.wrhapi.HandlerException;
import org.wymiwyg.wrhapi.HeaderName;
import org.wymiwyg.wrhapi.Request;
import org.wymiwyg.wrhapi.util.AcceptHeaderEntry;
import org.wymiwyg.wrhapi.util.InvalidPatternException;
import org.wymiwyg.wrhapi.util.RequestWrapper;

/**
 * Adds an text/html Accept header value if the header contained an xhtml value,
 * and vice-versa, adds an xhtml Accept header if the header contained an html one.
 * The q values of the new headers are those of the old one.
 *
 * @author rbn
 */
class WrappedRequest extends RequestWrapper {

	public WrappedRequest(Request request) {
		super(request);
	}

	@Override
	public String[] getHeaderValues(HeaderName headerName) throws HandlerException {
		final String[] headerValues = super.getHeaderValues(headerName);
		if (headerName.equals(HeaderName.ACCEPT)) {
			List<String> newList = new ArrayList();
			AcceptHeaderEntry htmlHdr=null, xhtmlHdr=null;
			for(int i=0; i<headerValues.length;i++) {
				try {
					final AcceptHeaderEntry entry = new AcceptHeaderEntry(headerValues[i]);
					if ( entry.getRange().match(Xhtml2HtmlFilter.htmlMimeType)) htmlHdr = entry;
					else if ( entry.getRange().match(Xhtml2HtmlFilter.xhtmlMimeType)) xhtmlHdr = entry;
					else newList.add(entry.toString());
				} catch (InvalidPatternException e) {
				}
			}
			if ( htmlHdr!=null && xhtmlHdr==null ) {
				newList.add( "application/xhtml+xml;q="+htmlHdr.getQ());
			}
			return newList.toArray(new String[newList.size()]);
		} else {
			return headerValues;
		}
	}



}
