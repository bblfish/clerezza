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
package org.wymiwyg.wrhapi;

import java.io.IOException;

import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;

/**
 * Represents the body of an HTTP-messsage.
 * 
 * The data can either be read from the ReadableByteChannel returned by the
 * read()-method or have it written to a WritableByteChannel by invoking the
 * writeTo-method.
 * 
 * An instance of this class must be set as the body of a response, Implementors
 * usually subclass <code>org.wymiwyg.wrhapi.util.MessageBody2Read</code> or
 * <code>org.wymiwyg.wrhapi.util.MessageBody2Write</code>, two abstract
 * classes providing implementation of one method from the other.
 * 
 * @author reto
 * 
 */

public interface MessageBody {

	/**
	 * writes the content to the spefified channel
	 * 
	 * @param out
	 *            the channel to which the content is to be written
	 * @throws IOException
	 */
	public void writeTo(WritableByteChannel out) throws IOException;

	/**
	 * @return a channle from which the content can be read
	 * @throws IOException
	 */
	public ReadableByteChannel read() throws IOException;
}
