/*
 * Copyright (c) 2008 trialox.org (trialox AG, Switzerland).
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wymiwyg.wrhapi.util.pathmappings;

import org.wymiwyg.wrhapi.HandlerException;
import org.wymiwyg.wrhapi.Request;
import org.wymiwyg.wrhapi.RequestURI;
import org.wymiwyg.wrhapi.util.RequestURIWrapper;
import org.wymiwyg.wrhapi.util.RequestWrapper;

/**
 *
 * @author reto
 */
class PrefixRemovingRequest extends RequestWrapper {
	private String pathPrefix;
	private String uniquePath;

	public PrefixRemovingRequest(Request request, String path, String uniquePath) {
		super(request);
		this.pathPrefix = path;
		this.uniquePath = uniquePath;
	}

	@Override
	public RequestURI getRequestURI() throws HandlerException {
		return new RequestURIWrapper(super.getRequestURI()) {

			@Override
			public String getAbsPath() {
				return removePrefix(super.getAbsPath());
			}

			@Override
			public String getPath() {
				return removePrefix(super.getPath());
			}

			private String removePrefix(String requestPath) {
				return "/" + (requestPath.startsWith(uniquePath) ?
					requestPath.substring(uniquePath.length()) 
					: requestPath.substring(pathPrefix.length()));

			}
			
		};
	}

	
}
