/*
 * Created on 18.02.2004
 *
 * This Exception is thrown when trying to instanciate a ContentTypePattern with an invalid pattern
 */
package org.wymiwyg.wrhapi.util;

/**
 * @author reto
 *
 */
public class InvalidPatternException extends Exception {

	/**
	 * 
	 */
	private static final long serialVersionUID = -8054959769631976110L;

	/**
	 * @param message
	 */
	public InvalidPatternException(String message) {
		super(message);
	}

}
