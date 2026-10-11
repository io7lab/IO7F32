// io7 IOT Device
#include <ConfigPortal32.h>
#include <WiFiClientSecure.h>
#include <ArduinoJson.h>
#include <SPIFFS.h>
#include <PubSubClient.h>
#include <HTTPUpdate.h>
#include <ESPmDNS.h>
#include <mbedtls/x509_crt.h>

const char compile_date[] = __DATE__ " " __TIME__;
char cmdTopic[200]      = "iot3/%s/cmd/+/fmt/+";
char evtTopic[200]      = "iot3/%s/evt/status/fmt/json";
char connTopic[200]     = "iot3/%s/evt/connection/fmt/json";
char logTopic[200]      = "iot3/%s/mgmt/device/status";
char metaTopic[200]     = "iot3/%s/mgmt/device/meta";
char updateTopic[200]   = "iot3/%s/mgmt/device/update";
char rebootTopic[200]   = "iot3/%s/mgmt/initiate/device/reboot";
char resetTopic[200]    = "iot3/%s/mgmt/initiate/device/factory_reset";
char upgradeTopic[200]  = "iot3/%s/mgmt/initiate/firmware/update";

String user_config_html = ""
    "<p><input type='text' name='broker' placeholder='Broker'>"
    "<style>"
    "  input[type='checkbox'] {"
    "    width: 40px;"
    "    height: 40px;"
    "    cursor: pointer;"
    "    margin-left: 20px;"
    "    vertical-align: middle;"
    "  }"
    "  .ssl-container {"
    "    background-color: #f0f0f0;"
    "    padding: 20px;"
    "    margin: 20px auto;"
    "    width: 90%;"
    "    border-radius: 0.3rem;"
    "    border: 2px solid #1fa3ec;"
    "  }"
    "</style>"
    "<div style='margin-left:50px; font-family:Arial; font-size:3em; color:rgb(175,175,175)'>"
    "   Use SSL : <input type='checkbox' name='ssl' value='true'/>"
    "</div>"
    "<p><input type='text' name='devId' placeholder='Device Id'>"
    "<p><input type='text' name='token' placeholder='Device Token'>"
    "<p><input type='text' name='meta.pubInterval' placeholder='Publish Interval'>";

String cert_html = ""
    "<html><head><title>MQTT Server Certificate</title></head><body>"
        "<style>"
            "input {font-size:3em; width:90%%; text-align:center;}"
            "textarea {font-size:1em; width:90%%; text-align:left; height:10em;}"
            "button { border:0;border-radius:0.3rem;background-color:#1fa3ec;"
            "color:#fff; line-height:2em;font-size:3em;width:90%%;}"
        "</style>"
        "<center><h1>Certificate</h1>%s"
        "<form action='/cert_save' method='post' enctype='multipart/form-data'>"
            "<p><textarea type='text' name='cert' placeholder=\"Default Let's Encrypt certificate\">%s</textarea>"
            "<p><button type='submit'>Save</button>"
        "</form></center>"
    "</body></html>";

String cert_error_html = ""
    "<html><head><title>Certificate Not Saved</title></head><body><center>"
        "<h1>The pasted text is not a valid certificate</h1>"
        "<p>It did not parse as a PEM X.509 certificate. Check that every"
        " -----BEGIN CERTIFICATE----- block is complete with its -----END"
        " CERTIFICATE----- line.</p>"
        "<p><button type='button' onclick=\"location.href='/check_ssl'\">Back to the certificate page</button></p>"
    "</center></body></html>";

String cert_default_html = ""
    "<html><head><title>Certificate Cleared</title></head><body><center>"
        "<h5>Stored certificate removed</h5>"
        "<h5>The default Let's Encrypt certificate will be used</h5>"
        "<p><button type='button' onclick=\"location.href='/reboot'\">Reboot</button>"
    "</center></body></html>";

String new_redirect_html = ""
    "<html><head><meta http-equiv='refresh' content='0; URL=/check_ssl' /></head>"
    "<body><p>Redirecting</body></html>";

extern String       user_html;

WebServer           server(80);
WiFiClientSecure    wifiClientSecure;
WiFiClient          wifiClient;
PubSubClient        client;
char                iot_server[100];
char                msgBuffer[JSON_CHAR_LENGTH];
unsigned long       pubInterval;
int                 mqttPort;

char                caFile[] = "/ca.pem";
String              ca = ""
   "-----BEGIN CERTIFICATE-----\n"
   "MIICjDCCAhGgAwIBAgIQTfOxXdbAeExQfNN7WObxFTAKBggqhkjOPQQDAzAuMQsw\n"
   "CQYDVQQGEwJVUzENMAsGA1UEChMESVNSRzEQMA4GA1UEAxMHUm9vdCBZRTAeFw0y\n"
   "NTA5MDMwMDAwMDBaFw0yODA5MDIyMzU5NTlaMDMxCzAJBgNVBAYTAlVTMRYwFAYD\n"
   "VQQKEw1MZXQncyBFbmNyeXB0MQwwCgYDVQQDEwNZRTIwdjAQBgcqhkjOPQIBBgUr\n"
   "gQQAIgNiAARxmrQzkdbEEL3MqXt3dJQttYc47axkdDTHud5TPqM2z5uSD5cmk0Wr\n"
   "HlWXvnlvqBLqiB34kluxIbmMyAiq3/YD6e80/vV259K8XQIdjFXloYOa0mIU71f7\n"
   "HQ09PvYDlw+jge4wgeswDgYDVR0PAQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUF\n"
   "BwMBMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFLlZ8o7PIvCG0zdI/3YU\n"
   "GLqC2FWHMB8GA1UdIwQYMBaAFKPIJlqOoUzQNWP8myPIOq5W809WMDIGCCsGAQUF\n"
   "BwEBBCYwJDAiBggrBgEFBQcwAoYWaHR0cDovL3llLmkubGVuY3Iub3JnLzATBgNV\n"
   "HSAEDDAKMAgGBmeBDAECATAnBgNVHR8EIDAeMBygGqAYhhZodHRwOi8veWUuYy5s\n"
   "ZW5jci5vcmcvMAoGCCqGSM49BAMDA2kAMGYCMQDIcnw5dcZLN9ffynXnnkLD/itS\n"
   "JEycJPb3sRkzeqBowup7vOsAwaqoCnNn/jh9wycCMQCJM6CPlaOC4pQYYbJtVPYb\n"
   "DKrIb2EKk5NpOpE6/XttQYZV/3gilB9l+Cc/DOVwmyg=\n"
   "-----END CERTIFICATE-----\n";

void handleIOTCommand(char* topic, byte* payload, unsigned int payloadLength);
void (*userCommand)(char* topic, JsonDocument* root) = NULL;
void (*userMeta)() = NULL;

// Returns the number of certificates that failed to parse as PEM/DER X.509
static int checkX509Pem(const String& pem) {
    mbedtls_x509_crt chain;
    mbedtls_x509_crt_init(&chain);
    int errors = mbedtls_x509_crt_parse(&chain,
                    (const unsigned char*)pem.c_str(), pem.length() + 1);
    mbedtls_x509_crt_free(&chain);
    return errors < 0 ? 999 : errors;    // parse-level failure counts as invalid
}

bool subscribeTopic(const char* topic) {
    if (client.subscribe(topic)) {
        Serial.printf("Subscription to %s OK\n", topic);
        return true;
    } else {
        Serial.printf("Subscription to %s Failed\n", topic);
        return false;
    }
}

void setDevId(char* topic, const char* devId) {
    char buffer[200];
    sprintf(buffer, topic, devId);
    strcpy(topic, buffer);
}

void initDevice() {
    loadConfig();
    if (LittleFS.exists(caFile)) {
        File f = LittleFS.open(caFile, "r");
        String stored = f.readString();
        stored.trim();
        f.close();
        if (checkX509Pem(stored) == 0) {  // validate before trusting
            ca = stored;
        } else {
            Serial.println("/ca.pem does not parse as a certificate: keeping the built-in default CA");
        }
    }

    if (!cfg.containsKey("config") || strcmp((const char*)cfg["config"], "done")) {
// MODIFY HERE FOR CERTIFICATE
        user_config_html = user_config_html + user_html;
        webServer.on("/check_ssl", [](){
            if (cfg.containsKey("ssl") &&  strcmp((const char*)cfg["ssl"], "true") == 0) {
                const char* note = LittleFS.exists(caFile)
                    ? "<p>Storing a user certificate. Clear the field and press Save to revert to the default.</p>"
                    : "<p>No user certificate stored. The default Let's Encrypt certificate will be used.</p>";
                String prefill = LittleFS.exists(caFile) ? ca : "";
                // the CA may be a multi-certificate chain of several KB: size
                // the page buffer on the heap, a stack buffer would overflow
                char* page = new (std::nothrow) char[cert_html.length() + ca.length() + 200];
                if (page) {
                    sprintf(page, cert_html.c_str(), note, prefill.c_str());
                    webServer.send(200, "text/html", page);
                    delete[] page;
                }
            } else {
                webServer.send(200, "text/html", postSave_html);
            }
        });
        webServer.on("/cert_save", HTTP_POST, [](){
            String pasted = webServer.arg("cert");
            pasted.trim();
            if (pasted.length() == 0) {
                // empty field: revert to the built-in default
                LittleFS.remove(caFile);
                ca = "";
                webServer.send(200, "text/html", cert_default_html);
            } else if (checkX509Pem(pasted) == 0) {
                // a paste must parse as PEM X.509 or it is refused
                File out = LittleFS.open(caFile, "w");
                out.print(pasted);
                out.close();
                ca = pasted;
                webServer.send(200, "text/html", postSave_html);
            } else {
                webServer.send(200, "text/html", cert_error_html);
            }
        });
        redirect_html = new_redirect_html;
        configDevice();
    } else {
        const char* devId = (const char*)cfg["devId"];
        const char* ssl = "false";
        if (cfg.containsKey("ssl")) {
            ssl = (const char*)cfg["ssl"];
        }
        setDevId(evtTopic, devId);
        setDevId(logTopic, devId);
        setDevId(connTopic, devId);
        setDevId(metaTopic, devId);
        setDevId(cmdTopic, devId);
        setDevId(updateTopic, devId);
        setDevId(rebootTopic, devId);
        setDevId(resetTopic, devId);
        setDevId(upgradeTopic, devId);
        sprintf(iot_server, "%s", (const char*)cfg["broker"]);
        if (strcmp(ssl, "true") == 0) {
            wifiClientSecure.setCACert(ca.c_str());
            client.setClient(wifiClientSecure);
            mqttPort = 8883;
        } else {
            client.setClient(wifiClient);
            mqttPort = 1883;
        }
    }
}

void set_iot_server() {
    client.setCallback(handleIOTCommand);
    if (mqttPort == 8883) {
        if (!wifiClientSecure.connect(iot_server, mqttPort)) {
            Serial.println("ssl connection failed");
            return;
        }
    } else {
        if (!wifiClient.connect(iot_server, mqttPort)) {
            Serial.println("connection failed");
            return;
        }
    }
    client.setServer(iot_server, mqttPort);  // IOT
}

void pubMeta() {
    JsonObject meta = cfg["meta"];
    StaticJsonDocument<512> root;
    JsonObject d = root.createNestedObject("d");
    JsonObject metadata = d.createNestedObject("metadata");
    for (JsonObject::iterator it = meta.begin(); it != meta.end(); ++it) {
        metadata[it->key().c_str()] = it->value();
    }
    JsonObject supports = d.createNestedObject("supports");
    supports["deviceActions"] = true;
    serializeJson(root, msgBuffer);
    Serial.printf("publishing device metadata: %s\n", msgBuffer);
    client.publish(metaTopic, msgBuffer, true);
}

void iot_connect() {
    while (!client.connected()) {
        int mqConnected = 0;
        mqConnected = client.connect((const char*)cfg["devId"],
                                     (const char*)cfg["devId"],
                                     (const char*)cfg["token"],
                                     connTopic,
                                     0,
                                     true,
                                     "{\"d\":{\"status\":\"offline\"}}",
                                     true);
        if (mqConnected) {
            Serial.println("MQ connected");
        } else {
            if (digitalRead(RESET_PIN) == 0) {
                reboot();
            }
            if (WiFi.status() == WL_CONNECTED) {
                if (client.state() == -2) {
                    set_iot_server();
                } else {
                    Serial.printf("MQ Connection fail RC = %d, try again in 5 seconds\n", client.state());
                }
                delay(5000);
            } else {
                Serial.println("Reconnecting to WiFi");
                WiFi.disconnect();
                WiFi.begin();
                int i = 0;
                while (WiFi.status() != WL_CONNECTED) {
                    Serial.print("*");
                    delay(5000);
                    if (i++ > 10) reboot();
                }
            }
        }
    }
    if (!subscribeTopic(rebootTopic)) return;
    if (!subscribeTopic(resetTopic)) return;
    if (!subscribeTopic(updateTopic)) return;
    if (!subscribeTopic(upgradeTopic)) return;
    if (!subscribeTopic(cmdTopic)) return;
    pubMeta();
    client.publish(connTopic, "{\"d\":{\"status\":\"online\"}}", true);
}

void update_progress(int cur, int total) {
    Serial.printf("CALLBACK:  HTTP update process at %d of %d bytes...\n", cur, total);
}

void update_error(int err) {
    Serial.printf("CALLBACK:  HTTP update fatal error code %d\n", err);
}

void handleIOTCommand(char* topic, byte* payload, unsigned int payloadLength) {
    byte2buff(msgBuffer, payload, payloadLength);
    StaticJsonDocument<512> root;
    deserializeJson(root, String(msgBuffer));
    JsonObject d = root["d"];

    if (strstr(topic, rebootTopic)) {  // rebooting
        reboot();
    } else if (strstr(topic, resetTopic)) {  // clear the configuration and reboot
        reset_config();
        ESP.restart();
    } else if (strstr(topic, updateTopic)) {
        JsonArray fields = d["fields"];
        for (JsonArray::iterator it = fields.begin(); it != fields.end(); ++it) {
            DynamicJsonDocument field = *it;
            const char* fieldName = field["field"];
            if (strstr(fieldName, "metadata")) {
                JsonObject fieldValue = field["value"];
                cfg.remove("meta");
                JsonObject meta = cfg.createNestedObject("meta");
                for (JsonObject::iterator fv = fieldValue.begin(); fv != fieldValue.end(); ++fv) {
                    meta[(char*)fv->key().c_str()] = fv->value();
                }
                save_config_json();
            }
        }
        pubMeta();
        pubInterval = cfg["meta"]["pubInterval"];
        if (userMeta) {
            userMeta();
        }
    } else if (strstr(topic, upgradeTopic)) {
        JsonObject upgrade = d["upgrade"];
        String response = "{\"OTA\":{\"status\":";
        if(upgrade.containsKey("fw_url")) {
		    Serial.println("firmware upgrading");
            const char* fw_url = upgrade["fw_url"];
            WiFiClient cli;
            HTTPUpdate httpUpdate;
            httpUpdate.onProgress(update_progress);
            httpUpdate.onError(update_error);
            client.publish(logTopic,"{\"info\":{\"upgrade\":\"Device will be upgraded.\"}}" );
            t_httpUpdate_return ret = httpUpdate.update(cli, fw_url);
	            switch(ret) {
		            case HTTP_UPDATE_FAILED:
                        response += "\"[update] Update failed. " + String(fw_url) + "\"}}";
                        client.publish(logTopic, (char*)response.c_str());
                        Serial.println(response);
		                break;
		            case HTTP_UPDATE_NO_UPDATES:
                        response += "\"[update] Update no Update.\"}}";
                        client.publish(logTopic, (char*) response.c_str());
                        Serial.println(response);
		                break;
		            case HTTP_UPDATE_OK:
		                Serial.println("[update] Update ok."); // may not called we reboot the ESP
		                break;
	            }
        } else {
            response += "\"OTA Information Error\"}}";
            client.publish(logTopic, (char*) response.c_str());
            Serial.println(response);
        }
    } else if (strstr(topic, "/cmd/")) {
        if (d.containsKey("config")) {
            char maskBuffer[JSON_CHAR_LENGTH];
            cfg["compile_date"] = compile_date;
            maskConfig(maskBuffer);
            cfg.remove("compile_date");
            String info = String("{\"config\":") + String(maskBuffer) + String("}");
            client.publish(logTopic, info.c_str());
        } else if (userCommand) {
            userCommand(topic, &root);
        }
    }
}