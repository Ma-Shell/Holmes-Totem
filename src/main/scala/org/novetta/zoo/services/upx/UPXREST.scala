package org.novetta.zoo.services.upx

import dispatch.Defaults._
import dispatch.{url, _}
import org.json4s.JsonAST.{JString, JValue}
import org.novetta.zoo.types.{TaskedWork, WorkFailure, WorkResult, WorkSuccess}
import collection.mutable


case class UPXWork(key: Long, filename: String, TimeoutMillis: Int, WorkType: String, Worker: String, Arguments: List[String]) extends TaskedWork {
  def doWork()(implicit myHttp: dispatch.Http): Future[WorkResult] = {

    val uri = UPXREST.constructURL(Worker, filename, Arguments)
    val requestResult = myHttp(url(uri) OK as.String)
      .either
      .map({
      case Right(content) =>
        UPXSuccess(true, JString(content), Arguments)

      case Left(StatusCode(404)) =>
        UPXFailure(false, JString("Not found (File already deleted?)"), Arguments)

      case Left(StatusCode(500)) =>
        UPXFailure(false, JString("UPX service failed, check local logs"), Arguments) //would be ideal to print response body here

      case Left(StatusCode(code)) =>
        UPXFailure(false, JString("Some other code: " + code.toString), Arguments)

      case Left(something) =>
        UPXFailure(false, JString("wildcard failure: " + something.toString), Arguments)
    })
    requestResult
  }
}


case class UPXSuccess(status: Boolean, data: JValue, Arguments: List[String], routingKey: String = "upx.result.static.totem", WorkType: String = "UPX") extends WorkSuccess
case class UPXFailure(status: Boolean, data: JValue, Arguments: List[String], routingKey: String = "", WorkType: String = "UPX") extends WorkFailure


object UPXREST {
  def constructURL(root: String, filename: String, arguments: List[String]): String = {
    arguments.foldLeft(new mutable.StringBuilder(root+filename))({
      (acc, e) => acc.append(e)}).toString()
  }
}
