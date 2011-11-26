/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.apache.clerezza.foafssl.auth

import java.security.interfaces.RSAPublicKey
import org.apache.clerezza.foafssl.ontologies.CERT
import java.util.LinkedList
import org.apache.clerezza.rdf.scala.utils._
import java.security.PublicKey
import scala.None
import org.apache.clerezza.platform.security.auth.WebIdPrincipal
import org.apache.clerezza.rdf.core._
import impl.TypedLiteralImpl
import org.apache.clerezza.rdf.ontologies.XSD
import java.math.BigInteger
import org.slf4j.scala.Logging

object WebIDClaim {
  def hex(bytes: Array[Byte]): String = bytes.dropWhile(_ == 0).map("%02X" format _).mkString
  val integerTypes = Set(XSD.integer,XSD.int_,XSD.positiveInteger, XSD.nonNegativeInteger)
}


/**
 * An X509 Claim maintains information about the proofs associated with claims
 * found in an X509 Certificate. It is the type of object that can be passed
 * into the public credentials part of a Subject node
 *
 * todo: think of what this would look like for a chain of certificates
 *
 * @author bblfish
 * @created 30/03/2011
 */
class WebIDClaim(val webId: UriRef, val key: PublicKey) extends Logging {
   import WebIDClaim._

  val errors = new LinkedList[java.lang.Throwable]()

	lazy val principal = new WebIdPrincipal(webId)
	var verified = Verification.Unverified

	/**
	 * verify this claim
	 * @param authSrvc: the authentication service contains information about where to get graphs
	 */
	//todo: make this asynchronous
	def verify(authSrvc: FoafSslAuthentication) {
		if (!webId.getUnicodeString.startsWith("http:") && !webId.getUnicodeString.startsWith("https:")) {
			//todo: ftp, and ftps should also be doable, though content negoations is then lacking
			verified = Verification.Unsupported
			return
		}
		verified = try {
			var webIdInfo = authSrvc.webIdSrvc.getWebIdInfo(webId)
			verify(webIdInfo.localPublicUserData) match {
				case None => Verification.Verified
				case Some(err) => {
					webIdInfo.forceCacheUpdate()
					webIdInfo = authSrvc.webIdSrvc.getWebIdInfo(webId)
					verify(webIdInfo.localPublicUserData) match {
						case None => Verification.Verified
						case Some(err) => {
							errors.add(err)
							Verification.Failed
						}
					}
				}
			}
		} catch {
			case e => {
				errors.add(e)
				Verification.Failed
			}
		}
	}

	def verify(tc: TripleCollection): Option[WebIDVerificationError] = {
		key match {
			case k: RSAPublicKey => if (verify(k, tc)) return None else Some(new WebIDVerificationError("No matching key in profile"))
			case x => Some(new WebIDVerificationError("Unsupported key format "+x.getClass) )
		}
	}

  /**
   * SPARQL deals with datatype implications, or should. So writing the query in SPARQL would be a lot
   * shorter.
   */
	private def verify(publicKey: RSAPublicKey, tc: TripleCollection): Boolean = {
    import WebIDClaim.hex
    val modulusLit = new TypedLiteralImpl(hex(publicKey.getModulus.toByteArray), XSD.hexBinary)
    val id = new RichGraphNode(modulusLit,tc);
//    Serializer.getInstance().serialize(System.out,tc,"text/turtle")

    // test if node is the exponent in the public key
    def exponentOk(exp: RichGraphNode): Boolean = exp.getNode match {
        case lit: TypedLiteral if  integerTypes contains lit.getDataType => try {
          val bi = new BigInteger(lit.getLexicalForm.trim())
          bi.equals(publicKey.getPublicExponent)
        } catch {
          case ex => logger.warn("problem comparing exponents...", ex)
          false
        }
        case _ => false
      }

    (id/-CERT.modulus) exists  { key =>
      if (tc.filter(webId,CERT.key,key.getNode).hasNext) {  //then we just need to check the exponent ...
         (key/CERT.exponent) exists { exponentOk(_) }
       } else false
    }
  }

	def canEqual(other: Any) = other.isInstanceOf[WebIDClaim]

	override
	def equals(other: Any): Boolean =
		other match {
			case that: WebIDClaim => (that eq this) || (that.canEqual(this) && webId == that.webId && key == that.key)
			case _ => false
		}

	override
	lazy val hashCode: Int = 41 * (
		41 * (
			41 + (if (webId != null) webId.hashCode else 0)
			) + (if (key != null) key.hashCode else 0)
		)
}

class WebIDVerificationError(msg: String) extends Error(msg) {

}




object Verification extends Enumeration {

	/**
	 * the claim has not yet been verified
	 */
	val Unverified = Value

	/**
	 * The claim was verified and succeeded
	 */
	val Verified = Value


	/**
	 * The claim was verified and failed
	 */
	val Failed = Value

	/**
	 * The claim cannot be verified by this agent
	 */
	val Unsupported = Value

}

