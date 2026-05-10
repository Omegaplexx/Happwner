package com.happwner

import org.json.JSONArray
import org.json.JSONObject
import java.net.URLEncoder

object LinkConverter {
    fun convert(input: String): String {
        val res = StringBuilder()
        input.lines().forEach { line ->
            val t = line.trim()
            if (t.isEmpty()) return@forEach
            
            // Пытаемся обработать как JSON
            if (t.startsWith("{") || t.startsWith("[")) {
                try {
                    if (t.startsWith("[")) {
                        val arr = JSONArray(t)
                        for (i in 0 until arr.length()) {
                            val obj = arr.getJSONObject(i)
                            val converted = processJson(obj)
                            if (converted != null) res.append(converted).append("\n")
                            else res.append(obj.toString()).append("\n")
                        }
                    } else {
                        val obj = JSONObject(t)
                        val converted = processJson(obj)
                        if (converted != null) res.append(converted).append("\n")
                        else res.append(t).append("\n")
                    }
                    return@forEach
                } catch (_: Exception) {}
            }
            
            // Пытаемся обработать как Base64
            val decoded = tryDecodeBase64(t)
            if (decoded != null) {
                res.append(convert(decoded)).append("\n")
            } else {
                res.append(t).append("\n")
            }
        }
        return res.toString().trim()
    }

    private fun tryDecodeBase64(input: String): String? {
        if (input.length < 10) return null
        return try {
            val data = android.util.Base64.decode(input, android.util.Base64.DEFAULT)
            val decoded = String(data, Charsets.UTF_8)
            if (decoded.contains("{") || decoded.contains("[") || decoded.contains("://")) {
                decoded
            } else null
        } catch (e: Exception) {
            null
        }
    }

    private fun processJson(root: JSONObject): String? {
        if (isShadowsocks(root)) {
            return buildShadowsocks(root, root.optString("remarks", ""))
        }
        
        // Sing-box style root objects
        val protocol = root.optString("protocol", root.optString("type"))
        when (protocol) {
            "vmess" -> return buildVmess(root, root.optString("tag", root.optString("remarks", "")))
            "tuic" -> return buildTuic(root, root.optString("tag", root.optString("remarks", "")))
        }

        val obs = root.optJSONArray("outbounds")
        if (obs != null) {
            val rem = root.optString("remarks", "")
            for (i in 0 until obs.length()) {
                val ob = obs.getJSONObject(i)
                val p = ob.optString("protocol", ob.optString("type"))
                when (p) {
                    "vless" -> {
                        val c = buildVless(ob, rem)
                        if (c != null) return c
                    }
                    "vmess" -> {
                        val c = buildVmess(ob, rem)
                        if (c != null) return c
                    }
                    "shadowsocks" -> {
                        val c = buildShadowsocks(ob, rem)
                        if (c != null) return c
                    }
                    "trojan" -> {
                        val c = buildTrojan(ob, rem)
                        if (c != null) return c
                    }
                    "hysteria2" -> {
                        val c = buildHysteria2(ob, rem)
                        if (c != null) return c
                    }
                    "tuic" -> {
                        val c = buildTuic(ob, rem)
                        if (c != null) return c
                    }
                    else -> {
                       if (isShadowsocks(ob)) return buildShadowsocks(ob, rem)
                    }
                }
            }
        }
        return null
    }

    private fun isShadowsocks(obj: JSONObject): Boolean {
        if (obj.has("server") && obj.has("server_port") && obj.has("password") && obj.has("method")) return true
        val settings = obj.optJSONObject("settings")
        if (settings != null) {
            val servers = settings.optJSONArray("servers")
            if (servers != null && servers.length() > 0) {
                val s = servers.getJSONObject(0)
                if (s.has("address") && s.has("port") && s.has("password") && s.has("method")) return true
            }
        }
        return false
    }

    private fun buildVless(ob: JSONObject, rem: String): String? {
        val s = ob.optJSONObject("settings") ?: return null
        val vnext = s.optJSONArray("vnext") ?: return null
        if (vnext.length() == 0) return null
        val vn = vnext.getJSONObject(0)
        val users = vn.optJSONArray("users") ?: return null
        if (users.length() == 0) return null
        val u = users.getJSONObject(0)
        val ss = ob.optJSONObject("streamSettings")
        val rs = ss?.optJSONObject("realitySettings")
        val enc = URLEncoder.encode(rem, "UTF-8").replace("+", "%20")
        return "vless://${u.getString("id")}@${vn.getString("address")}:${vn.getInt("port")}?encryption=${u.optString("encryption","none")}&flow=${u.optString("flow","")}&fp=${rs?.optString("fingerprint","chrome")}&pbk=${rs?.optString("publicKey","")}&security=${ss?.optString("security","none")}&sid=${rs?.optString("shortId","")}&sni=${rs?.optString("serverName","")}&type=${ss?.optString("network","tcp")}#$enc"
    }

    private fun buildVmess(ob: JSONObject, rem: String): String? {
        return try {
            val linkJson = JSONObject()
            linkJson.put("v", "2")
            
            val settings = ob.optJSONObject("settings")
            val vnext = settings?.optJSONArray("vnext")?.optJSONObject(0)
            
            val addr = ob.optString("server", vnext?.optString("address", "") ?: "")
            val port = if (ob.has("server_port")) ob.getInt("server_port") else vnext?.optInt("port", 0) ?: 0
            val uuid = ob.optString("uuid", vnext?.optJSONArray("users")?.optJSONObject(0)?.optString("id", "") ?: "")
            
            linkJson.put("add", addr)
            linkJson.put("port", port.toString())
            linkJson.put("id", uuid)
            linkJson.put("aid", "0")
            linkJson.put("scy", "auto")
            
            val transport = ob.optJSONObject("transport")
            val stream = ob.optJSONObject("streamSettings")
            val net = transport?.optString("type") ?: stream?.optString("network") ?: "tcp"
            linkJson.put("net", net)
            
            val tlsObj = ob.optJSONObject("tls")
            val isTls = tlsObj?.optBoolean("enabled") ?: (stream?.optString("security") == "tls")
            linkJson.put("tls", if (isTls) "tls" else "")
            
            if (net == "ws") {
                val ws = transport ?: stream?.optJSONObject("wsSettings")
                linkJson.put("path", ws?.optString("path"))
                val host = ws?.optJSONObject("headers")?.optString("Host") ?: ws?.optString("headers")
                if (host != null) linkJson.put("host", host)
            }

            val finalRem = if (ob.has("tag")) ob.getString("tag") else (if (ob.has("remarks")) ob.getString("remarks") else rem)
            linkJson.put("ps", finalRem)

            val base64 = android.util.Base64.encodeToString(linkJson.toString().toByteArray(), android.util.Base64.NO_WRAP)
            "vmess://$base64"
        } catch (_: Exception) { null }
    }

    private fun buildShadowsocks(ob: JSONObject, rem: String): String? {
        return try {
            val address: String
            val port: Int
            val method: String
            val password: String
            if (ob.has("server")) {
                address = ob.getString("server")
                port = ob.getInt("server_port")
                method = ob.getString("method")
                password = ob.getString("password")
            } else {
                val settings = ob.optJSONObject("settings")
                val s = settings?.optJSONArray("servers")?.getJSONObject(0) ?: return null
                address = s.getString("address")
                port = s.getInt("port")
                method = s.getString("method")
                password = s.getString("password")
            }
            val credentials = "$method:$password"
            val ui = android.util.Base64.encodeToString(credentials.toByteArray(), android.util.Base64.NO_WRAP)
            val finalRem = if (ob.has("remarks")) ob.getString("remarks") else rem
            val encRem = URLEncoder.encode(finalRem, "UTF-8").replace("+", "%20")
            "ss://$ui@$address:$port#$encRem"
        } catch (_: Exception) { null }
    }

    private fun buildTrojan(ob: JSONObject, rem: String): String? {
        return try {
            val settings = ob.optJSONObject("settings")
            val server = settings?.optJSONArray("servers")?.optJSONObject(0) ?: return null
            val address = server.optString("address")
            val port = server.optInt("port")
            val password = server.optString("password")

            val ss = ob.optJSONObject("streamSettings")
            val network = ss?.optString("network")
            val security = ss?.optString("security")

            val query = mutableMapOf<String, String>()
            if (!network.isNullOrEmpty()) query["type"] = network
            
            if (security == "tls" || security == "reality") {
                val tls = ss.optJSONObject("tlsSettings") ?: ss.optJSONObject("realitySettings")
                val sni = tls?.optString("serverName")
                if (!sni.isNullOrEmpty()) {
                    query["sni"] = sni
                    query["host"] = sni
                }
            }

            if (network == "ws") {
                val ws = ss?.optJSONObject("wsSettings")
                val path = ws?.optString("path")
                val host = ws?.optJSONObject("headers")?.optString("Host")
                if (!path.isNullOrEmpty()) query["path"] = path
                if (!host.isNullOrEmpty()) query["host"] = host
            }

            val queryStr = query.toList().sortedBy { it.first }.joinToString("&") {
                "${it.first}=${URLEncoder.encode(it.second, "UTF-8")}"
            }

            val queryString = if (queryStr.isNotEmpty()) "?$queryStr" else ""
            val encPass = URLEncoder.encode(password, "UTF-8")
            val finalRem = if (ob.has("remarks")) ob.getString("remarks") else rem
            val encRem = URLEncoder.encode(finalRem, "UTF-8").replace("+", "%20")

            "trojan://$encPass@$address:$port$queryString#$encRem"
        } catch (_: Exception) { null }
    }

    private fun buildHysteria2(ob: JSONObject, rem: String): String? {
        return try {
            val settings = ob.optJSONObject("settings")
            val server = settings?.optJSONArray("servers")?.optJSONObject(0) ?: return null
            val address = server.optString("address")
            val port = server.optInt("port")
            
            val ss = ob.optJSONObject("streamSettings")
            val hy2 = ss?.optJSONObject("hy2Settings")
            val password = hy2?.optString("password")
            val obfs = hy2?.optJSONObject("obfs")
            val obfsType = obfs?.optString("type")
            val obfsPassword = obfs?.optString("password")
            
            val tls = ss?.optJSONObject("tlsSettings")
            val sni = tls?.optString("serverName")
            
            val query = StringBuilder()
            if (!obfsType.isNullOrEmpty()) query.append("&obfs=").append(obfsType)
            if (!obfsPassword.isNullOrEmpty()) query.append("&obfs-password=").append(URLEncoder.encode(obfsPassword, "UTF-8"))
            if (!sni.isNullOrEmpty()) query.append("&sni=").append(sni)
            
            val queryString = if (query.isNotEmpty()) "?" + query.toString().substring(1) else ""
            val encRem = URLEncoder.encode(rem, "UTF-8").replace("+", "%20")
            
            "hysteria2://$password@$address:$port/$queryString#$encRem"
        } catch (_: Exception) { null }
    }

    private fun buildTuic(ob: JSONObject, rem: String): String? {
        return try {
            val address = ob.optString("server")
            val port = ob.optInt("server_port")
            val uuid = ob.optString("uuid")
            val password = ob.optString("password")

            val query = mutableMapOf<String, String>()
            val cc = ob.optString("congestion_control")
            if (cc.isNotEmpty()) query["congestion_control"] = cc
            
            val mode = ob.optString("udp_relay_mode")
            if (mode.isNotEmpty()) query["udp_relay_mode"] = mode

            val tls = ob.optJSONObject("tls")
            if (tls != null && tls.optBoolean("enabled", false)) {
                val sni = tls.optString("server_name")
                if (sni.isNotEmpty()) query["sni"] = sni
                
                val alpnArr = tls.optJSONArray("alpn")
                if (alpnArr != null && alpnArr.length() > 0) {
                    query["alpn"] = alpnArr.getString(0)
                }
                
                if (tls.optBoolean("insecure", false)) {
                    query["allow_insecure"] = "1"
                }
            }

            val queryStr = query.toList().sortedBy { it.first }.joinToString("&") {
                "${it.first}=${URLEncoder.encode(it.second, "UTF-8")}"
            }
            val queryString = if (queryStr.isNotEmpty()) "?$queryStr" else ""
            
            val finalRem = if (ob.has("tag")) ob.getString("tag") else (if (ob.has("remarks")) ob.getString("remarks") else rem)
            val encRem = URLEncoder.encode(finalRem, "UTF-8").replace("+", "%20")
            
            "tuic://$uuid:$password@$address:$port$queryString#$encRem"
        } catch (e: Exception) { null }
    }
}
