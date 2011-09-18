/*
 *  Copyright 2009 reto.
 * 
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 * 
 *       http://www.apache.org/licenses/LICENSE-2.0
 * 
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *  under the License.
 */

package org.wymiwyg.wrhapi.osgi;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.WritableByteChannel;

/**
 *
 * @author reto
 */
public class FirstWriteOrCloseActionChannel implements WritableByteChannel {

	private WritableByteChannel base;
	private Runnable action;
	private boolean first = true;

	public FirstWriteOrCloseActionChannel(WritableByteChannel base, Runnable action) {
		this.base = base;
		this.action = action;
	}

	public int write(ByteBuffer src) throws IOException {
		if (first) {
			if (src.remaining() > 0) {
				action.run();
				first = false;
			}
		}
		return base.write(src);
	}

	public boolean isOpen() {
		return base.isOpen();
	}

	public void close() throws IOException {
		if (first) {
			action.run();
			first = false;
		}
		base.close();
	}

}
