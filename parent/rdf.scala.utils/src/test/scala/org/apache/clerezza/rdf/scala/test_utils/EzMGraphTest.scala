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
// the package starts with test, in order to simulate non package level access
package test.org.apache.clerezza.rdf.scala.test_utils

import org.apache.clerezza.rdf.core._
import impl._
import org.apache.clerezza.rdf.ontologies._
import org.junit._

// we don't import all of the package so that we can test package access (not done thoroughly yet)
import org.apache.clerezza.rdf.scala.utils.context

/**
 * In these test classes the implicit imports are brought in very carefully, as they also need to
 * be tested
 *
 * @author bblfish, reto
 */ 
class EzMGraphTest {

	val bblfishModulus = """
    9D ☮ 79 ☮ BF ☮ E2 ☮ F4 ☮ 98 ☮ BC ☮ 79 ☮ 6D ☮ AB ☮ 73 ☮ E2 ☮ 8B ☮ 39 ☮ 4D ☮ B5 26 ✜ 68 ✜ 49 ✜ EE ✜ 71 ✜ 87 ✜
    06 ✜ 32 ✜ C9 ✜ 9F ✜ 3F ✜ 94 ✜ E5 ✜ CB ✜ 4D ✜ B5 12 ☮ 35 ☮ 13 ☮ 69 ☮ 60 ☮ 81 ☮ 58 ☮ 79 ☮ 66 ☮ F3 ☮ 79 ☮ 20 ☮
    91 ☮ 6A ☮ 3F ☮ 42 5A ✜ F6 ✜ 54 ✜ 42 ✜ 88 ✜ B2 ✜ E9 ✜ 19 ✜ 4A ✜ 79 ✜ 87 ✜ 2E ✜ 62 ✜ 44 ✜ 2D ✜ 7C 06 ☽ 78 ☽ F8
    ☽ FD ☽ 52 ☽ 92 ☽ 6D ☽ CD ☽ D6 ☽ F3 ☽ 28 ☽ 6B ☽ 1F ☽ DB ☽ CB ☽ D3 F2 ☮ 08 ☮ 34 ☮ 72 ☮ A2 ☮ 12 ☮ 75 ☮ AE ☮ D1
    ☮ 09 ☮ 17 ☮ D0 ☮ 88 ☮ 4C ☮ 04 ☮ 8E 04 ☾ E5 ☾ BF ☾ D1 ☾ 41 ☾ 64 ☾ D1 ☾ F7 ☾ 89 ☾ 6D ☾ 8B ☾ B2 ☾ F2 ☾ 46 ☾ C0
    ☾ 56 87 ☮ 8D ☮ B8 ☮ 7C ☮ C6 ☮ FE ☮ E9 ☮ 61 ☮ 88 ☮ 08 ☮ 61 ☮ DD ☮ E3 ☮ B8 ☮ B5 ☮ 47 ♥
    """

	/**import some references in order to reduce dependencies */

	final val hex: UriRef = new UriRef("http://www.w3.org/ns/auth/cert#hex")
	final val identity: UriRef = new UriRef("http://www.w3.org/ns/auth/cert#identity")
	final val RSAPublicKey: UriRef = new UriRef("http://www.w3.org/ns/auth/rsa#RSAPublicKey")
	final val modulus: UriRef = new UriRef("http://www.w3.org/ns/auth/rsa#modulus")
	final val public_exponent: UriRef = new UriRef("http://www.w3.org/ns/auth/rsa#public_exponent")

	val henryUri: String = "http://bblfish.net/#hjs"
	val retoUri: String = "http://farewellutopia.com/reto/#me"
	val danbriUri: String = "http://danbri.org/foaf.rdf#danbri"


	private val tinyGraph: Graph = {
		val gr = new SimpleMGraph
		val reto = new BNode()
		val danny = new BNode()
		val henry = new UriRef(henryUri)

		gr.add(new TripleImpl(reto, RDF.`type`, FOAF.Person))
		gr.add(new TripleImpl(reto, FOAF.name, new PlainLiteralImpl("Reto Bachman-Gmür", new Language("rm"))))
		//it is difficult to remember that one needs to put a string literal if one does not want to specify a language
		gr.add(new TripleImpl(reto, FOAF.title, new TypedLiteralImpl("Mr", XSD.string)))
		gr.add(new TripleImpl(reto, FOAF.currentProject, new UriRef("http://clerezza.org/")))
		gr.add(new TripleImpl(reto, FOAF.knows, henry))
		gr.add(new TripleImpl(reto, FOAF.knows, danny))

		gr.add(new TripleImpl(danny, FOAF.name, new PlainLiteralImpl("Danny Ayers", new Language("en"))))
		gr.add(new TripleImpl(danny, RDF.`type`, FOAF.Person))
		gr.add(new TripleImpl(danny, FOAF.knows, henry))
		gr.add(new TripleImpl(danny, FOAF.knows, reto))

		gr.add(new TripleImpl(henry, FOAF.name, new TypedLiteralImpl("Henry Story", XSD.string))) //It is tricky to remember that one needs this for pure strings
		gr.add(new TripleImpl(henry, FOAF.currentProject, new UriRef("http://webid.info/")))
		gr.add(new TripleImpl(henry, RDF.`type`, FOAF.Person))
		gr.add(new TripleImpl(henry, FOAF.knows, danny))
		gr.add(new TripleImpl(henry, FOAF.knows, reto))

		val pk = new BNode()
		gr.add(new TripleImpl(pk, RDF.`type`, RSAPublicKey))
		gr.add(new TripleImpl(pk, identity, henry))
		gr.add(new TripleImpl(pk, modulus, LiteralFactory.getInstance().createTypedLiteral(65537)))
		gr.add(new TripleImpl(pk, public_exponent, new TypedLiteralImpl(bblfishModulus, hex)))
		gr.getGraph
	}


	@Test
	def singleTriple {
		import org.apache.clerezza.rdf.scala.utils._



		val expected = {
			val s = new SimpleMGraph
			s.add(new TripleImpl(henryUri.uri, FOAF.knows, retoUri.uri))
			s.getGraph
		}
		val ez = new context() {
			uri(henryUri) -- FOAF.knows --> retoUri.uri
		}
		Assert.assertEquals("The two graphs should be equals", expected, ez.graph.getGraph)
	}

	@Test
	def inverseTriple {
		import org.apache.clerezza.rdf.scala.utils._
		val expected = {
			val s = new SimpleMGraph
			s.add(new TripleImpl(retoUri.uri, FOAF.knows, henryUri.uri))
			s.getGraph
		}
		val ez = new context {
			uri(henryUri) <--  FOAF.knows -- retoUri.uri
		}
		Assert.assertEquals("The two graphs should be equals", expected, ez.graph.getGraph)
	}

	@Test
	def twographs {
		import org.apache.clerezza.rdf.scala.utils._

		val ez1 = new context {
			b_("reto") -- FOAF.name --> "Reto Bachman-Gmür".lang("rm")
		}.graph

		Assert.assertEquals("the two graphs should be equal",1,ez1.size)

		new context(ez1) {
			b_("reto") -- FOAF.homepage --> "http://bblfish.net/".uri
		}
		Assert.assertEquals("ez1 has grown by one",2,ez1.size)

		//now a second graph

		val ez2 = new context {
			b_("hjs") -- FOAF.name --> "Henry Story"
		}.graph

		new context(ez2) {
		   b_("hjs") -- FOAF.homepage --> "http://bblfish.net/".uri
		}
		Assert.assertEquals("ez1 is the same size as it used to be",2,ez1.size)
		Assert.assertEquals("ez2 has grown by one",2,ez2.size)

		new context(ez1) {
			b_("reto") -- FOAF.currentProject --> "http://clerezza.org/".uri
		}
		Assert.assertEquals("ez1 has grown by one",3,ez1.size)


	}

	/**
	 * On Scala list
	 * https://groups.google.com/d/msg/scala-user/IsJ1yXjd2lw/KXwKk1wXtSIJ
	 */
	@Test
	def antiPatternDiscussion {
		import org.apache.clerezza.rdf.scala.utils.Preamble.string2lit

		val uriA = "http://bblfish.net/".uri
		val uriB = "http://danbri.org/foaf.rdf#danbri".uri
		val uriC = "http://farewellutopia.com/reto/#me".uri
		val uriD = "http://danny.ayers.name/index.rdf#me".uri

		val graphA = new SimpleMGraph()
		val graphB = new SimpleMGraph()

		graphA.add(new TripleImpl(uriA,FOAF.knows,uriB))
		graphA.add(new TripleImpl(uriB,FOAF.name,"Dan Brickley"))
		graphB.add(new TripleImpl(uriA,FOAF.knows,uriC))
		graphB.add(new TripleImpl(uriC,FOAF.knows,uriD))

		Assert.assertEquals("graph A contains two statements",2,graphA.getGraph.size)
		Assert.assertEquals("graph B contains two statements",2,graphB.getGraph.size)


		val graphA4 = new context {
			uriA  -- FOAF.knows --> ( uriB -- FOAF.name --> "Dan Brickley" )
		}.graph
		val graphB4 = new context {
			uriA  -- FOAF.knows --> ( uriC --  FOAF.knows --> uriD )
		}.graph

		Assert.assertEquals("graph A contains two statements",2, graphA4.getGraph.size)
		Assert.assertEquals("graph B contains two statements",2, graphB4.getGraph.size)
		Assert.assertEquals("graph A is isomorphic with graph A2", graphA.getGraph, graphA4.getGraph)
		Assert.assertEquals("graph B is isomorphic with graph B2", graphB.getGraph, graphB4.getGraph)

	}



	@Test
	def usingAsciiArrows {
		import org.apache.clerezza.rdf.scala.utils._

		val ez = new context {(
			b_("reto").a(FOAF.Person) -- FOAF.name --> "Reto Bachman-Gmür".lang("rm")
				-- FOAF.title --> "Mr"
				-- FOAF.currentProject --> "http://clerezza.org/".uri
				-- FOAF.knows --> (
					"http://bblfish.net/#hjs".uri.a(FOAF.Person)
						-- FOAF.name --> "Henry Story"
				      -- FOAF.currentProject --> "http://webid.info/".uri
				      -- FOAF.knows -->>> List(b_("reto"), b_("danny"))
				  //one need to list properties before inverse properties, or use brackets
				  <-- identity -- (
						   bnode.a(RSAPublicKey) //. notation because of precedence of operators
							   -- modulus --> 65537
							   -- public_exponent --> (bblfishModulus^^hex) // brackets needed due to precedence
						   )  
				)
				-- FOAF.knows --> (
					b_("danny").a(FOAF.Person)
						-- FOAF.name --> "Danny Ayers".lang("en")
				      -- FOAF.knows --> "http://bblfish.net/#hjs".uri //knows
						-- FOAF.knows --> b_("reto")
				)
		)}.graph

		Assert.assertEquals("the two graphs should be of same size",tinyGraph.size,ez.size)
		Assert.assertEquals("Both graphs should contain exactly the same triples",tinyGraph,ez.getGraph)
		//We can add triples by creating a new anonymous instance
		new context(ez) {(
			uri("http://bblfish.net/#hjs") -- FOAF.name --> "William"
					-- FOAF.name --> "Bill"
		)}
		Assert.assertEquals("the triple colletion has grown by two",tinyGraph.size()+2,ez.size)

		new context(ez) { b_("danny") -- FOAF.name --> "George" }
		Assert.assertEquals("the triple collection has grown by one",tinyGraph.size()+3,ez.size)
	}

}
