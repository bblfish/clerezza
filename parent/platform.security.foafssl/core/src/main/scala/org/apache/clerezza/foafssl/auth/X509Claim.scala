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

import javax.security.auth.Refreshable
import java.security.cert.X509Certificate
import org.slf4j.LoggerFactory
import java.util.Date
import org.apache.clerezza.rdf.core._

/**
 * Static methods for X509Claim. It makes it easier to read code when one knows which methods
 * have no need of any object state and which do. These methods could be moved to a library.
 * @author bblfish
 */
object X509Claim {
  final val logger = LoggerFactory.getLogger(classOf[X509Claim])

  import scala.collection.JavaConversions._
  /**
   * Extracts the URIs in the subject alternative name extension of an X.509
   * certificate
   *
   * @param cert X.509 certificate from which to extract the URIs.
   * @return Iterator of URIs as strings found in the subjectAltName extension.
   */
	def getClaimedWebIds(cert: X509Certificate): Iterator[String] =
    if (cert == null) Iterator.empty
    else cert.getSubjectAlternativeNames() match {
      case coll if (coll != null) => {
        for (sanPair <- coll if (sanPair.get(0) == 6)) yield sanPair(1).asInstanceOf[String]
      }.iterator
      case _ => Iterator.empty
    }
}

  /**
 * An X509 Claim maintains information about the proofs associated with claims
 * found in an X509 Certificate. It is the type of object that can be passed
 * into the public credentials part of a Subject node
 *
 * todo: think of what this would look like for a chain of certificates
 *
 * @author bblfish
 * @created: 30/03/2011
 */
class X509Claim(val cert: X509Certificate) extends Refreshable {

  import X509Claim._
  val claimReceivedDate = new Date();
  lazy val tooLate = claimReceivedDate.after(cert.getNotAfter())
  lazy val tooEarly = claimReceivedDate.before(cert.getNotBefore())

  /* a list of unverified principals */
  lazy val webidclaims = getClaimedWebIds(cert).map {
    str => {
      val webid = new UriRef(str);
      new WebIDClaim(webid, cert.getPublicKey)
    }
  }.toSet


  //note could also implement Destroyable
  //
  //http://download.oracle.com/javase/6/docs/technotes/guides/security/jaas/JAASRefGuide.html#Credentials
  //
  //if updating validity periods can also take into account the WebID reference, then it is possible
  //that a refresh could have as consequence to do a fetch on the WebID profile
  //note: one could also take the validity period to be dependent on the validity of the profile representation
  //in which case updating the validity period would make more sense.

  override
  def refresh() {
  }

  /* The certificate is currently within the valid time zone */
  override
  def isCurrent(): Boolean = !(tooLate||tooEarly)

   lazy val error = {}


  /**verify all the webids in the X509 */
  def verify(authService: FoafSslAuthentication) {
    webidclaims foreach {
      wid => wid.verify(authService)
    }
  }

  def canEqual(other: Any) = other.isInstanceOf[X509Claim]

  override
  def equals(other: Any): Boolean =
    other match {
      case that: X509Claim => (that eq this) || (that.canEqual(this) && cert == that.cert)
      case _ => false
    }

  override
  lazy val hashCode: Int = 41 * (41 +
    (if (cert != null) cert.hashCode else 0))


}

