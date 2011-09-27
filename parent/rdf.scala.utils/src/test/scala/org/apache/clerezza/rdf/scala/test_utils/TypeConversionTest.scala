package org.apache.clerezza.rdf.scala.test_utils

/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
import org.junit._
import org.apache.clerezza.rdf.core._
import impl.{TripleImpl, PlainLiteralImpl, TypedLiteralImpl}

class TypeConversionTest {

	private val literalFactory = LiteralFactory.getInstance()

	@Test
	def useStringAsObject {
		import org.apache.clerezza.rdf.scala.utils._
		val t = new TripleImpl(new UriRef(("http://example.org/subject")), new UriRef(("http://example.org/predicate")), "a value")
		Assert.assertEquals(literalFactory.createTypedLiteral("a value"), t.getObject)
	}

	/*@Test
	def useStringWithLanguageTag {
		val t = new TripleImpl(new UriRef(("http://example.org/subject")), new UriRef(("http://example.org/predicate")), "a value"("en"))
		Assert.assertEquals(new PlainLiteralImpl("a value", new Language("en")), t.getObject)
	}*/

	@Test
	def useStringWithLanguageTag {
		import org.apache.clerezza.rdf.scala.utils._

	   val lit = new PlainLiteralImpl("a value", new Language("en"))
		val t = new TripleImpl(new UriRef(("http://example.org/subject")), new UriRef(("http://example.org/predicate")), "a value" lang "en")
		Assert.assertEquals(lit, t.getObject)
	}

	@Test
	def useStringWithType {
		import org.apache.clerezza.rdf.scala.utils._

		val typeUri = new UriRef("http://example.org/dt")
		val t = new TripleImpl(new UriRef(("http://example.org/subject")), new UriRef(("http://example.org/predicate")), "a value"^^typeUri)
		Assert.assertEquals(new TypedLiteralImpl("a value", typeUri), t.getObject)
	}

	@Test
	def dotUri {
		import org.apache.clerezza.rdf.scala.utils._

		val t = new TripleImpl(new UriRef(("http://example.org/subject")), new UriRef(("http://example.org/predicate")), "http://example.org".uri)
		Assert.assertEquals(new UriRef("http://example.org"), t.getObject)
	}

}
