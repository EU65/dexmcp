package dev.dexmcp

import org.json.JSONArray
import org.json.JSONObject

fun jsonObject(vararg pairs: Pair<String, Any?>): JSONObject = JSONObject().apply {
    for ((key, value) in pairs) put(key, value ?: JSONObject.NULL)
}

fun jsonArray(values: Iterable<Any?>): JSONArray = JSONArray().apply {
    values.forEach { put(it ?: JSONObject.NULL) }
}

fun JSONObject.stringList(name: String): List<String> {
    val array = optJSONArray(name) ?: return emptyList()
    return (0 until array.length()).mapNotNull { array.optString(it).takeIf(String::isNotBlank) }
}
