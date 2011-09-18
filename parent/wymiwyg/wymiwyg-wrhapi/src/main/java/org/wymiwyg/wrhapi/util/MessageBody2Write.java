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

import java.nio.channels.Pipe;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.Pipe.SinkChannel;


/**
 * @author reto
 *
 */
public abstract class MessageBody2Write implements MessageBody {
    /* (non-Javadoc)
     * @see org.wymiwyg.wrhapi.MessageBody#read()
     */
    public ReadableByteChannel read() throws IOException {
        final Pipe pipe = Pipe.open();
        new Thread() {
                public void run() {
                    try {
                    	SinkChannel sinkChannel = pipe.sink();
                        writeTo(sinkChannel);
                        sinkChannel.close();
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }
                }
            }.start();

        return pipe.source();
    }
}
