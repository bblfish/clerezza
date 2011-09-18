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

import org.wymiwyg.wrhapi.MessageBody;

import java.io.IOException;

import java.nio.ByteBuffer;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;


/**
 * @author reto
 *
 */
public abstract class MessageBody2Read implements MessageBody {
    /* (non-Javadoc)
     * @see org.wymiwyg.wrhapi.MessageBody#writeTo(java.nio.channels.WritableByteChannel)
     */
    public void writeTo(WritableByteChannel out) throws IOException {
        ReadableByteChannel in = read();
        ByteBuffer buffer = ByteBuffer.allocateDirect(4096);
        while (in.read(buffer) != -1) {
        	buffer.flip();
        	while (buffer.remaining() > 0) {
        		out.write(buffer);
        	}
        	buffer.clear();
        }
    }
}
