package dev.dexmcp

import io.github.libxposed.service.XposedService
import io.github.libxposed.service.XposedServiceHelper
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Client for the LSPosed framework service (libxposed/service, API 102).
 *
 * The framework delivers a binder once the module app launches. Starting with API 102
 * the module can ask to add packages to its scope at runtime: LSPosed shows the request
 * to the user, and the answer arrives through [XposedService.OnScopeEventListener].
 */
object ScopeClient {
    private val connectedState = MutableStateFlow(false)
    private val scopeState = MutableStateFlow<Set<String>>(emptySet())
    private val serviceState = MutableStateFlow<XposedService?>(null)

    @Volatile
    private var registered = false

    val connected: StateFlow<Boolean> = connectedState.asStateFlow()
    val scope: StateFlow<Set<String>> = scopeState.asStateFlow()

    fun init(context: android.content.Context) {
        if (registered) return
        registered = true
        runCatching {
            XposedServiceHelper.registerListener(object : XposedServiceHelper.OnServiceListener {
                override fun onServiceBind(service: XposedService) {
                    serviceState.value = service
                    connectedState.value = true
                    scopeState.value = readScope(service)
                    AppLog.info("LSPosed：已连接 ${service.frameworkName}，API ${service.apiVersion}")
                }

                override fun onServiceDied(service: XposedService) {
                    if (serviceState.compareAndSet(service, null)) {
                        connectedState.value = false
                        scopeState.value = emptySet()
                        AppLog.warn("LSPosed：服务已断开")
                    }
                }
            })
        }.onFailure {
            AppLog.warn("LSPosed：服务监听注册失败 ${it.message ?: it.javaClass.simpleName}")
        }
    }

    fun refreshScope() {
        serviceState.value?.let { scopeState.value = readScope(it) }
    }

    fun requestScope(pkg: String, callback: (Boolean, String?) -> Unit) {
        val service = serviceState.value
        if (service == null) {
            callback(false, "LSPosed service is not connected")
            return
        }
        runCatching {
            service.requestScope(listOf(pkg), object : XposedService.OnScopeEventListener {
                override fun onScopeRequestApproved(approved: List<String>) {
                    scopeState.value = scopeState.value + approved
                    callback(true, null)
                }

                override fun onScopeRequestFailed(message: String) {
                    callback(false, message)
                }
            })
        }.onFailure { callback(false, it.message ?: it.javaClass.simpleName) }
    }

    fun removeScope(pkg: String) {
        val service = serviceState.value ?: return
        runCatching {
            service.removeScope(listOf(pkg))
            scopeState.value = scopeState.value - pkg
        }
    }

    private fun readScope(service: XposedService): Set<String> =
        runCatching { service.scope.toSet() }.getOrDefault(emptySet())
}
