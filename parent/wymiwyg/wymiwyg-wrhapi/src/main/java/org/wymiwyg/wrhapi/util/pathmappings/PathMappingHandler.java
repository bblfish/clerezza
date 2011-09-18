/*
 * Copyright 2008 WYMIWYG (http://wymiwyg.org)
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
package org.wymiwyg.wrhapi.util.pathmappings;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import org.wymiwyg.wrhapi.Handler;
import org.wymiwyg.wrhapi.HandlerException;
import org.wymiwyg.wrhapi.Request;
import org.wymiwyg.wrhapi.Response;
import org.wymiwyg.wrhapi.ResponseStatus;

/**
 * This handler forwards requests to a Handler repsonsible for a specific 
 * uri space section.
 * 
 * With <code>addHandler</code> handlers are assigned to a path, requests 
 * are forwarded.
 * 
 * @author reto
 */
public class PathMappingHandler implements Handler {

	private Map<String, Handler> pathHandlerMap = new HashMap<String, Handler>();

	/**
	 * binds a handler to a specified path. for every request at most one 
	 * non-overlay handler is executed, overlay handler are executed in the
	 * order thea have been added, till one of them returns a non 4XX rersponse.
	 *
	 * @param handler
	 * @param path indicating a prefix if it ends with '/', otherwise an exact path
	 * @param uid an uid of the handler
	 * @param removePrefixInRequests
	 * @param overlay true if this handler is an overlay.
	 */
	public void addHandler(Handler handler, String path, String uid,
			boolean removePrefixInRequests, boolean overlay) {
		if (handler == null) {
			throw new IllegalArgumentException("handler may not be null");
		}
		String uniquePath;
		if (path.charAt(path.length() - 1) == '/') {
			uniquePath = path + uid + '/';
		} else {
			uniquePath = path + '/' + uid;
		}
		if (pathHandlerMap.containsKey(uniquePath)) {
			throw new RuntimeException(
					"The path " + uniquePath + " must be unique ");
		}
		final RegisteredHandler registeredHandler = new RegisteredHandler(
				handler, path, uniquePath, removePrefixInRequests);

		pathHandlerMap.put(uniquePath, registeredHandler);
		if (pathHandlerMap.containsKey(path)) {
			Handler existing = pathHandlerMap.get(path);
			//this might also be set to an update MultiSelectHandler
			Handler newHandler;
			if (overlay) {
				newHandler = new OverlayHandler(registeredHandler, existing);
			} else {
				MultiSelectHandler multiSelectHandler;
				if (existing instanceof MultiSelectHandler) {
					multiSelectHandler = (MultiSelectHandler) existing;
				} else {
					multiSelectHandler = new MultiSelectHandler();
					String existingUid =
							((RegisteredHandler) existing).uniquePath;
					multiSelectHandler.addOption(existingUid);
				}
				multiSelectHandler.addOption(uniquePath);
				newHandler = multiSelectHandler;
			}
			pathHandlerMap.put(path, newHandler);
		} else {
			pathHandlerMap.put(path, registeredHandler);
		}

	}

	public void handle(Request request, Response response) throws HandlerException {
		String requestPath = request.getRequestURI().getPath();
		Handler handler = getHandler(requestPath);
		if (handler != null) {
			handler.handle(request, response);
		} else {
			response.setResponseStatus(ResponseStatus.NOT_FOUND);
		}
	}

	private static class RegisteredHandler implements Handler {

		Handler handler;
		String path;
		String uniquePath;
		boolean removePrefixInRequests;

		public RegisteredHandler(Handler handler, String path, String uniquePath,
				boolean removePrefixInRequests) {
			this.handler = handler;
			this.path = path;
			this.uniquePath = uniquePath;
			this.removePrefixInRequests = removePrefixInRequests;
		}

		public void handle(Request request, Response response) throws HandlerException {
			if (removePrefixInRequests) {
				request = new PrefixRemovingRequest(request, path, uniquePath);
			}
			handler.handle(request, response);
		}
	}

	private Handler getHandler(String requestPath) {
		Handler result = pathHandlerMap.get(requestPath);
		if (result != null) {
			return result;
		}
		if (requestPath.length() <= 1) {
			return null;
		} else {
			String remainingPath = requestPath.substring(0, requestPath.
					lastIndexOf('/', requestPath.length() - 2) + 1);
			return getHandler(remainingPath);
		}

	}
}
