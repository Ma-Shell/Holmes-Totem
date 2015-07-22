package org.novetta.zoo.types

import java.util.concurrent.ExecutorService

import com.typesafe.config.Config
import com.typesafe.scalalogging.Logger
import org.json4s.JsonAST.{JString, JValue}
import org.novetta.zoo.services.{MetadataSuccess, MetadataWork, YaraSuccess, YaraWork}
import org.slf4j.LoggerFactory

import scala.collection.JavaConversions._
import scala.concurrent.Future
import scala.util.Random


/**
 * This trait is inherited by all work tasks to be done by Totem. TaskedWork is the superclass which all typechecking and
 * matching is done against.
 *
 * Traits do not have constructors; this trait has the following values which all children must set
 * {{{
 *   val key: Long => The message key associated with this work
 *   val filename: String => The filename that refers to this work's instance on disk
 *   val WorkType: String => The type of work that needs to be performed
 *   val Worker: String => The ActorPath that will operate on this work
 * }}}
 *
 * Currently, we require explicitly set actor paths for processing. This is slightly burdensome, but as these actor paths
 * can be specified in the overall system, this is not an excessive reqirement.
 *
 * To add a new analytic or enricher, you must
 *    - Create an appropriate case class below, inheriting from TaskedWork
 *    - Create an appropriate Result class below, inheriting from WorkResult
 *    - Add that actor case class to the WorkEncoding.enumerateWork matching function
 *    - Add the WorkResult classes to the WorkEncoding.workRoutingKey matching functions
 *    - Specify an ActorPath
 *    - Create an appropriate Actor (in the described path) to handle the request
 *    - Deploy the actor in question
 *
 * @constructor None. This is a trait.
 *
 */
//object types {
//  type partial  = String => Future[WorkResult]
//}

trait TaskedWork {

  val key: Long
  val filename: String
  val TimeoutMillis: Int
  val WorkType: String
  val Worker: String
  val Arguments: List[String]
  def doWork()(implicit myHttp: dispatch.Http): Future[WorkResult]

}
/**
 * HashWork case class. Holds the tasking and worker path appropriate for this TaskedWork
 * @param key: Long => The message key associated with this work
 * @param filename: String => The filename that refers to this work's instance on disk
 * @param WorkType: String => The type of work that needs to be performed
 * @param Worker: String => The ActorPath that will operate on this work
 *
 * @constructor Create a new HashWork.
 *
 */

case class UnsupportedWork(key: Long, filename: String, TimeoutMillis: Int, WorkType: String, Worker: String, Arguments: List[String]) extends TaskedWork {
  import scala.concurrent.ExecutionContext.Implicits.global //this makes me uncomfortable, but this is an edge case to begin with.
  def doWork()(implicit myHttp: dispatch.Http): Future[WorkResult] = {
    Future{UnsupportedFailure(false, JString(""), Arguments, "", WorkType)}
  }
}
case class UnsupportedFailure(status: Boolean, data: JValue, Arguments: List[String], routingKey: String, WorkType: String) extends WorkFailure


/**
 * This trait is inherited by all work results generated by Totem. WorkResult is the superclass which all typechecking and
 * matching is done against.
 *
 * Traits do not have constructors; this trait has the following values which all children must set
 * {{{
 *   val key: Long => The message key associated with this work
 *   val data: String => The results of the worker. All workers MUST return some sane JSON element. Handling of this JSON element
 *      is to be done at DB ingest time.
 * }}}
 *
 * @constructor None. This is a trait.
 *
 */
trait WorkResult {
  val status: Boolean
  val data: JValue
  val routingKey: String
  val WorkType: String
  val Arguments: List[String]
}
abstract class WorkSuccess extends WorkResult
abstract class WorkFailure extends WorkResult

trait WorkEncoding {
  def GeneratePartial(work: String): String
  def enumerateWork(key: Long, filename: String, workToDo: Map[String, List[String]]): List[TaskedWork]
  def workRoutingKey(work: WorkResult): String
}
/**
 * This is a helper object, with one purpose - to ensure that JSON blobs can be properly decoded into useful work that Totem
 * can understand as a native Scala object.
 *
 * @constructor Create a new WorkEncoding Object.
 *
 */
class TotemEncoding(conf: Config) extends WorkEncoding {
  /**
   * Logic to create and route TaskedWork objects based on keywords in JSON blobs. In the event we get a blob and keyword
   * that we cannot deal with, we return nothing. Silently. Because we want to punish the developer for their arrogance.
   *
   * @return a List[TaskedWork]: We always return some work to be done. We purge Units from this list.
   * @param key: a String: ID of the message that generated this work.
   * @param filename: a String: The filename to be used as a reference to the file on disk.
   * @param workToDo: a List[String]: A list of the keywords from the ZooWork object.
   */

  val keys = conf.getObject("zoo.enrichers").keySet()
  val en = conf.getObject("zoo.enrichers").toConfig
  val services = keys.map(key =>
    (key, Random.shuffle(en.getStringList(s"$key.uri").toList))
  ).toMap[String, List[String]]
  val log = Logger(LoggerFactory.getLogger("name"))

  def GeneratePartial(work: String): String = {
    work match {
      case "FILE_METADATA" => Random.shuffle(services.getOrElse("metadata", List())).head
      case "HASHES" => Random.shuffle(services.getOrElse("hashes", List())).head
      case "PEINFO" => Random.shuffle(services.getOrElse("peinfo", List())).head
      case "VTSAMPLE" => Random.shuffle(services.getOrElse("vtsample", List())).head
      case "YARA" => Random.shuffle(services.getOrElse("yara", List())).head

    }
  }

  def enumerateWork(key: Long, filename: String, workToDo: Map[String, List[String]]): List[TaskedWork] = {

    val w = workToDo.map({
      case ("FILE_METADATA", li: List[String]) =>
        MetadataWork(key, filename, 60, "FILE_METADATA", GeneratePartial("FILE_METADATA"), li)
      case ("YARA", li: List[String]) =>
        YaraWork(key, filename, 60, "YARA", GeneratePartial("YARA"), li)
      case (s: String, li: List[String]) =>
        UnsupportedWork(key, filename, 1, s, GeneratePartial(s), li)
      case _ => Unit
    }).collect({
      case x: TaskedWork => x
    })
    w.toList
  }
  def workRoutingKey(work: WorkResult): String = {
    work match {
      case x: MetadataSuccess => "metadata.result.static.zoo"
      case x: YaraSuccess => "yara.result.static.zoo"
    }
  }
}
trait Resolution {
  val status: Boolean
}

case class ConsumerResolution(status: Boolean) extends Resolution //if we ackked
case class ResultResolution(status: Boolean) extends Resolution //if we transmitted the results
case class RemainderResolution(status: Boolean) extends Resolution //if we transmitted the remainder
case class LocalResolution(status: Boolean) extends Resolution //if all local actions are done
case class NackResolution(status: Boolean) extends Resolution //if we nackked

case class Conflict(consumer: Boolean, result: Boolean, remainder: Boolean, local: Boolean, nack: Boolean) {
  def +(that: Resolution): Conflict = that match {
    case ConsumerResolution(status: Boolean) => Conflict(status, this.result, this.remainder, this.local, this.nack)
    case ResultResolution(status: Boolean) => Conflict(this.consumer, status, this.remainder, this.local, this.nack)
    case RemainderResolution(status: Boolean) => Conflict(this.consumer, this.result, status, this.local, this.nack)
    case LocalResolution(status: Boolean) => Conflict(this.consumer, this.result, this.remainder, status, this.nack)
    case NackResolution(status: Boolean) => Conflict(this.consumer, this.result, this.remainder, this.local, status)
  }

}