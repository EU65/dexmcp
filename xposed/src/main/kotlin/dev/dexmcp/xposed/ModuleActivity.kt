package dev.dexmcp.xposed

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView

class ModuleActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(56, 96, 56, 56)
        }
        layout.addView(TextView(this).apply {
            text = """
                DexMCP Hook

                1. 在 LSPosed 里启用本模块，并把要注入的应用勾进作用域。
                2. 应用启动时（Application.onCreate 之前）会向 Dex MCP 请求注入。
                3. Dex MCP 用 android_frida_agent_set 写入的脚本加载完成后，应用才继续启动。
                4. Dex MCP 没运行、没有对应脚本或超时，应用照常启动。
            """.trimIndent()
            textSize = 15f
        })
        layout.addView(Button(this).apply {
            text = "打开 Dex MCP"
            setOnClickListener {
                runCatching {
                    startActivity(Intent().setClassName("dev.dexmcp", "dev.dexmcp.MainActivity"))
                }
            }
        })
        setContentView(layout)
    }
}
