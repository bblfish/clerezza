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
package org.apache.clerezza.shell;



import org.apache.felix.scr.annotations.Component;
import org.osgi.framework.BundleContext
import org.osgi.framework.BundleEvent
import org.osgi.framework.BundleListener
import org.osgi.service.component.ComponentContext;
import org.osgi.framework.Bundle
import java.io.{File, PrintWriter, Reader, StringWriter, BufferedReader, InputStreamReader, InputStream, Writer, OutputStream}
import java.lang.reflect.InvocationTargetException
import java.net._
import java.security.PrivilegedActionException
import java.security.AccessController
import java.security.PrivilegedAction

import javax.script.ScriptContext
import javax.script.{ScriptEngineFactory => JavaxEngineFactory, Compilable,
					 CompiledScript, ScriptEngine, AbstractScriptEngine, Bindings,
					 SimpleBindings, ScriptException}
import jline.CandidateListCompletionHandler
import jline.{CompletionHandler, Completor, Terminal, ConsoleReader, ArgumentCompletor}

//History => JHistory
import java.util.{ArrayList, Arrays}

//import scala.collection.immutable.Map
import scala.actors.DaemonActor
import scala.collection.immutable
import scala.tools.nsc._;
import scala.tools.nsc.interpreter._;
import scala.tools.nsc.io.{AbstractFile, PlainFile, VirtualDirectory}
import scala.tools.nsc.util._
import scala.tools.nsc.symtab.SymbolLoaders
import scala.tools.nsc.reporters.ConsoleReporter
import scala.tools.nsc.reporters.Reporter
import scala.tools.util.PathResolver
import scala.tools.nsc.util.{ClassPath, JavaClassPath}
import scala.actors.Actor
import scala.actors.Actor._
import org.apache.clerezza.scala.scripting._
import java.io.File
import scala.tools.nsc.interpreter.session.{JLineHistory => History}
import org.slf4j.scala.Logging

class Shell(factory: InterpreterFactory, val inStream: InputStream, 
			out: OutputStream, shellCommands: immutable.Set[ShellCommand]) extends Logging {


	private var bundleContext: BundleContext = null

	private var bindings = Set[(String, String, Any)]()
	private var imports = Set[String]()
	private var terminationListeners = Set[Shell.TerminationListener]();


	val interpreterLoop = new InterpreterLoop(new BufferedReader(new InputStreamReader(inStream)), new PrintWriter(out, true)) {
		override def createInterpreter() {
			intp = factory.createInterpreter(out)
			intp.beQuietDuring {
				for (binding <- bindings) {
					intp.bind(binding._1, binding._2, binding._3)
				}
				for (v <- imports) {
					intp.interpret("import "+v)
				}
			}
		}

		override val prompt = "zz>"

		override lazy  val standardCommands: List[LoopCommand] = {
			import LoopCommand._
			import Result._
			(for (shellCommand <- shellCommands) yield {
					new NullaryCmd(shellCommand.command, shellCommand.description, (line: String)=> {
							val (continue, linesToRecord) = shellCommand.execute(line, Shell.this.out)
							Result(continue, linesToRecord)
						})
				}).toList :::
			List(
				cmd("help",  "[command]","print this help message", helpCommand),
            historyCommand,
				cmd("h?","<string>", "search the history", searchHistory),
				cmd("load", "<path>","load and interpret a Scala file", loadCommand),
				nullary("power", "enable power user mode", powerCmd),
				nullary("quit", "terminate the console shell (use shutdown to shut down clerezza)", () => Result(false, None)),
				nullary("replay", "reset execution and replay all previous commands", replay),
				shCommand,
				nullary("silent", "disable/enable automatic printing of results", verbosity)
			)
		}

/*
		def printHelp() = {
			out println "This is a scala based console, it supports any Scala expression, as well as the command described below."
			out println "To access an OSGi service use $[interface]."
			out println ""
			out println "Initially the following variables are bound:"
			for ((name, boundType, value) <- bindings) {
				out println (name+": "+boundType+" = "+value)
			}
			out println ""
			out println "This are the initial imports: "
			for (v <- imports) {
				out println ("import "+v)
			}
			out println ""
			super.printWelcome()
		}
*/


/*		override def process(settings: Settings) {
			this.settings = settings
			createInterpreter()

//			sets in to some kind of reader depending on environmental cues
			in = new InteractiveReader() {

				override lazy val history = Some(History(consoleReader))
				override lazy val completion = Option(intp) map (x => new Completion(x))

				val consoleReader = {
					val terminal = new jline.UnixTerminal
//					val terminal = new jline.Terminal {
//						override def initializeTerminal() {logger.warn("JLINE: initializing echo")}
//
//						override def isEchoEnabled =  { logger.warn("JLINE: is enabled echo")
//						true}
//
//						override def isSupported = { logger.warn("JLINE: is supported echo")
//						true}
//
//						override def enableEcho() { logger.warn("JLINE: enabling echo")}
//
//						override def disableEcho() {logger.warn("JLINE: disabling echo") }
//
//						override def getTerminalHeight = 24
//
//						override def getTerminalWidth = 80
//
//						override def getEcho = false
//					}
					val r = new jline.ConsoleReader(inStream, out, null, terminal)
					r setHistory (History().jhistory)
					r setBellEnabled false
					completion foreach { c =>
						logger.warn("JLINE: adding completor : "+c.jline)
						r addCompletor c.jline
						r setAutoprintThreshhold 250
					}
					import java.util.List
					r setCompletionHandler new CompletionHandler {
						def complete(reader: ConsoleReader, candidates: List[_], pos: Int) = {
							val buffer = reader.getCursorBuffer()
							if (candidates.size == 1) {
								CandidateListCompletionHandler.setBuffer(reader, candidates.get(0).toString, pos)
							} else {
								import collection.JavaConversions._
								out.println()
								out.println(candidates.mkString("\t"))
								out.print(prompt)
								out.print(reader.getCursorBuffer())
							}
							true
						}
					}

				  r addCompletor new Completor {
						def complete(p1: String, p2: Int, candidates: java.util.List[_]) = {
							logger.warn("JLINE: candidates : "+candidates)
							val canStrings = candidates.asInstanceOf[List[String]]
							canStrings.add("Clerezza")
							canStrings.add("Apache")
							try {
								throw new RuntimeException
							} catch {
								case e => logger.warn("stack ", e)
							}
							0
						}
					}

					r
				}

				def readOneLine(prompt: String) = consoleReader readLine prompt
				val interactive = false
			}
		   //in = new SimpleReader(inStream, out, true)

			loadFiles(settings)
			try {
				// it is broken on startup; go ahead and exit
				if (interpreter.reporter.hasErrors) return

				printWelcome()

				// this is about the illusion of snappiness.  We call initialize()
				// which spins off a separate thread, then print the prompt and try
				// our best to look ready.  Ideally the user will spend a
				// couple seconds saying "wow, it starts so fast!" and by the time
				// they type a command the compiler is ready to roll.
				intp.initialize()
				loop()
			}
			finally closeInterpreter()
			true
		}
*/

		override def printWelcome() {
			import Properties._
			val welcomeMsg =
				"""|Welcome to the Apache Clerezza Console
				|Console is based on Scala %s (%s, Java %s).
				|Type in expressions to have them evaluated.
				|Hint: To execute a Felix-Shell command prepend ":f "
				|Type :help for more information.""" .
			stripMargin.format(versionString, javaVmName, javaVersion)

         echo(welcomeMsg)
		}

		private def echo(msg: String) = {
		  out println msg
		  out.flush()
		}

	}
	val console: Actor = new DaemonActor {
		def act() {
			try {
				interpreterLoop.process(Array[String]())
			} finally {
				for (l <- terminationListeners) {
					l.terminated
				}
				println("console terminated")
			}
		}
	}

	def start() {
		console.start
	}

	def stop() {
		interpreterLoop.command(":q")
		interpreterLoop.closeInterpreter()
	}

	def bind(name: String, boundType: String, value: Any) {
		bindings += ((name, boundType, value))
	}

	def addImport(importValue: String) {
		imports += importValue
	}

	def addTerminationListener(l: Shell.TerminationListener) {
		terminationListeners += l
	}

	def removeTerminationListener(l: Shell.TerminationListener) {
		terminationListeners -= l
	}

}
object Shell {
	trait TerminationListener {
		def terminated: Unit
	}
	
	trait Environment {
		val componentContext: ComponentContext;
		val in: InputStream;
		val out: OutputStream;
	}
}