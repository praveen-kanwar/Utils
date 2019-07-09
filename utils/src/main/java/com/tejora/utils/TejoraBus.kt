package com.tejora.utils

import io.reactivex.Observable
import io.reactivex.subjects.PublishSubject

/**
 * Publish Data On Subscribe Base
 */
@Suppress("unused")
object TejoraBus {
    private val publisher = PublishSubject.create<Any>()

    @Suppress("unused")
    fun publish(event: Any) {
        publisher.onNext(event)
    }

    // Listen should return an Observable and not the publisher
    // Using ofType we filter only events that match that class type
    @Suppress("unused")
    fun <T> listen(eventType: Class<T>): Observable<T> = publisher.ofType(eventType)
}