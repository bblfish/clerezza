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
package org.wymiwyg.wrhapi.filter.impl;

import org.wymiwyg.wrhapi.Handler;
import org.wymiwyg.wrhapi.HandlerException;
import org.wymiwyg.wrhapi.Request;
import org.wymiwyg.wrhapi.Response;
import org.wymiwyg.wrhapi.filter.Filter;

/**
 * @author reto
 *
 */
public class FilterRunner implements Handler {

	Filter filter;
	Handler next;
	
	/**
	 * creates a FilterRunner.
	 * 
	 * @param filters the filters to be executed
	 * @param terminator the terminator to be executed if all filters forward the request
	 */
	public FilterRunner(Filter[] filters, Handler terminator) {
		filter = filters[0];
		if (filters.length > 1) {
			Filter[] remainingFilters = new Filter[filters.length-1];
			System.arraycopy(filters, 1, remainingFilters, 0, remainingFilters.length);
			next = new FilterRunner(remainingFilters, terminator);
		} else {
			next = terminator;
		}
	}

	/* (non-Javadoc)
	 * @see org.wymiwyg.wrhapi.Handler#handle(org.wymiwyg.wrhapi.Request, org.wymiwyg.wrhapi.Response)
	 */
	public void handle(Request request, Response response)
			throws HandlerException {
		filter.handle(request, response, next);
	}

}
