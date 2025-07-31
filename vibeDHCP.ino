#include <WiFi.h>
#include <DNSServer.h>
#include <WebServer.h>

#include <esp_netif.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/udp.h"
#include "lwip/ip_addr.h"

// --- CONFIGURE AP ---
const char* ssid = "ESP32_AP";
const char* password = "12345678";
IPAddress apIP(192, 168, 4, 1);
IPAddress offeredIP(192, 168, 4, 77);
IPAddress netMsk(255, 255, 255, 0);
byte clientMac[6] = { 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01 };

DNSServer dnsServer;
WebServer server(80);

#define DNS_PORT 53
#define DHCP_SERVER_PORT 67
#define DHCP_CLIENT_PORT 68

WiFiUDP udp;
#define DHCP_BUFFER_SIZE 548
byte dhcpBuffer[DHCP_BUFFER_SIZE];

void writeByte(int offset, byte value) {
  dhcpBuffer[offset] = value;
}

void writeBytes(int offset, const byte* data, int length) {
  for (int i = 0; i < length; i++) {
    dhcpBuffer[offset + i] = data[i];
  }
}

void writeUInt16(int offset, uint16_t value) {
  dhcpBuffer[offset] = (value >> 8) & 0xFF;
  dhcpBuffer[offset + 1] = value & 0xFF;
}

void writeUInt32(int offset, uint32_t value) {
  dhcpBuffer[offset] = (value >> 24) & 0xFF;
  dhcpBuffer[offset + 1] = (value >> 16) & 0xFF;
  dhcpBuffer[offset + 2] = (value >> 8) & 0xFF;
  dhcpBuffer[offset + 3] = value & 0xFF;
}

int buildDHCPofferPacket(
  const byte* clientMac,
  uint32_t offeredIp,
  uint32_t serverIp,
  uint32_t transactionId
) {
  return buildDHCPpacket(clientMac, offeredIp, serverIp, transactionId, 0x02);
}

int buildDHCPackPacket(
  const byte* clientMac,
  uint32_t offeredIp,
  uint32_t serverIp,
  uint32_t transactionId
) {
  return buildDHCPpacket(clientMac, offeredIp, serverIp, transactionId, 0x05);
}

int buildDHCPpacket(
  const byte* clientMac,
  uint32_t offeredIp,
  uint32_t serverIp,
  uint32_t transactionId,
  byte messageType
) {
  memset(dhcpBuffer, 0, DHCP_BUFFER_SIZE);

  // BOOTP Header
  writeByte(0x00, 0x02); // op: BOOTREPLY
  writeByte(0x01, 0x01); // htype: Ethernet
  writeByte(0x02, 0x06); // hlen: MAC length
  writeByte(0x03, 0x00); // hops
  writeUInt32(0x04, transactionId);
  writeUInt16(0x08, 0x0000); // secs
  writeUInt16(0x0A, 0x8000); // flags - broadcast (rather than unicast)

  writeUInt32(0x0C, 0x00000000); // ciaddr
  writeUInt32(0x10, offeredIp);  // yiaddr
  writeUInt32(0x14, 0x00000000); // siaddr
  writeUInt32(0x18, 0x00000000); // giaddr

  writeBytes(0x1C, clientMac, 6); // chaddr

  // Magic cookie
  writeBytes(0xEC, (const byte*)"\x63\x82\x53\x63", 4);

  int opt = 0xF0;

  // DHCP Message Type
  writeByte(opt++, 0x35);          // Option 53
  writeByte(opt++, 0x01);
  writeByte(opt++, messageType);   // 0x02 or 0x05

  // Server Identifier (Option 54)
  writeByte(opt++, 0x36);
  writeByte(opt++, 0x04);
  writeUInt32(opt, serverIp); opt += 4;

  // Lease Time (Option 51) — 3600s
  writeByte(opt++, 0x33);
  writeByte(opt++, 0x04);
  writeUInt32(opt, 0x00000E10); opt += 4;

  // Subnet Mask (Option 1) — 255.255.255.0
  writeBytes(opt, (const byte*)"\x01\x04\xFF\xFF\xFF\x00", 6); opt += 6;

  // Router (Option 3)
  writeByte(opt++, 0x03);
  writeByte(opt++, 0x04);
  writeUInt32(opt, serverIp); opt += 4;

  // DNS (Option 6)
  writeByte(opt++, 0x06);
  writeByte(opt++, 0x04);
  writeUInt32(opt, serverIp); opt += 4;

  // Option 114: Captive Portal URI
  const char* portalURI = "http://192.168.4.1/portal";
  size_t uriLen = strlen(portalURI);

  writeByte(opt++, 114);              // Option 114
  writeByte(opt++, uriLen);           // Length of URI
  writeBytes(opt, (const byte*)portalURI, uriLen);
  opt += uriLen;

  // End Option (255)
  writeByte(opt++, 0xFF);

  return opt;
}

void stopDefaultDHCPServer() {
  esp_netif_t* netif = NULL;
  netif = esp_netif_get_handle_from_ifkey("WIFI_AP_DEF");
  if (netif) {
    esp_netif_dhcps_stop(netif); // stop default DHCP server
  }
}

// Minimal DHCP server (responds to DHCPDISCOVER with DHCPOFFER)
void dhcpServerTask(void *pvParameters) {
  udp.begin(DHCP_SERVER_PORT);
  while (1) {
    int packetSize = udp.parsePacket();
    if (packetSize) {
      uint8_t packet[512];
      udp.read(packet, packetSize);

      // Debug: print packet bytes to Serial
      Serial.print("Received packet (size ");
      Serial.print(packetSize);
      Serial.println("):");
      for (int i = 240; i < 243; i++) {
        Serial.printf("Byte[%d] %02X\n", i, packet[i]);
      }
      Serial.println();

      uint32_t xid = packet[0x04] << 24 | packet[0x05] << 16 | packet[0x06] << 8 | packet[0x07];
      Serial.printf("xid: %i\n", xid);

      memcpy(clientMac, &packet[0x1C], 6);
      Serial.printf("Client MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
                    clientMac[0], clientMac[1], clientMac[2],
                    clientMac[3], clientMac[4], clientMac[5]);

      if (packet[240] == 0x35) {
        if(packet[242] == 0x01) sendDHCPoffer(xid);  //DHCPDISCOVER
        if(packet[242] == 0x03) sendDHCPack(xid);    //DHCPREQUEST
      }
    }
    vTaskDelay(10 / portTICK_PERIOD_MS);
  }
}

void sendDHCPoffer(uint32_t xid) {
  Serial.println("sendDHCPoffer()");
  uint32_t offeredIp = (192UL << 24) | (168UL << 16) | (4UL << 8) | 77UL;
  uint32_t serverIp  = (192UL << 24) | (168UL << 16) | (4UL << 8) | 1UL;

  int packetLength = buildDHCPofferPacket(clientMac, offeredIp, serverIp, xid);
 
  // Send DHCPOFFER to client port
  udp.beginPacket(IPAddress(255,255,255,255), DHCP_CLIENT_PORT);
  udp.write(dhcpBuffer, packetLength);  //DHCP_BUFFER_SIZE
  udp.endPacket();
}

void sendDHCPack(uint32_t xid) {
  Serial.println("sendDHCPack()");

  uint32_t offeredIp = (192UL << 24) | (168UL << 16) | (4UL << 8) | 77UL;
  uint32_t serverIp  = (192UL << 24) | (168UL << 16) | (4UL << 8) | 1UL;

  int packetLength = buildDHCPackPacket(clientMac, offeredIp, serverIp, xid);
 
  // Send DHCPOFFER to client port
  udp.beginPacket(IPAddress(255,255,255,255), DHCP_CLIENT_PORT);
  udp.write(dhcpBuffer, packetLength);  //DHCP_BUFFER_SIZE
  udp.endPacket();
}

void setup() {
  Serial.begin(115200);
  // Start AP
  WiFi.softAP(ssid, password);
  delay(1000);

  WiFi.softAPConfig(apIP, apIP, netMsk);
  dnsServer.start(DNS_PORT, "*", apIP);

  stopDefaultDHCPServer();
  xTaskCreate(dhcpServerTask, "dhcpServerTask", 4096, NULL, 1, NULL);

  server.onNotFound([]() {
    server.send(200, "text/plain", server.uri());
  });
  server.begin();

  Serial.println("vibeDHCP Captive Portal running");
}

void loop() {
  server.handleClient();
  dnsServer.processNextRequest();
}