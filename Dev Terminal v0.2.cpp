#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define NOMINMAX

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <wincon.h>
#include <ipexport.h>
#include <icmpapi.h>
#include <iphlpapi.h>
#include <windns.h>
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include <functional>
#include <algorithm>
#include <cctype>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "dnsapi.lib")

static HANDLE g_conIn = NULL, g_conOut = NULL;
static std::vector<std::string> g_history;
static int g_histIndex = -1;

static void conWrite(const std::string& s) { DWORD n; WriteFile(g_conOut, s.data(), (DWORD)s.size(), &n, NULL); }
static void setColor(WORD color) { SetConsoleTextAttribute(g_conOut, color); }
static void resetColor() { setColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY); }
static void printError(const std::string& msg) { setColor(FOREGROUND_RED | FOREGROUND_INTENSITY); conWrite(msg + "\n"); resetColor(); }
static void printInfo(const std::string& msg) { setColor(FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY); conWrite(msg + "\n"); resetColor(); }

static int t_scan(const std::vector<std::string>&);
static int t_ping(const std::vector<std::string>&);
static int t_dns(const std::vector<std::string>&);
static int t_b64(const std::vector<std::string>&);
static int t_hash(const std::vector<std::string>&);
static int t_whois(const std::vector<std::string>&);
static int t_http(const std::vector<std::string>&);
static int t_ftp(const std::vector<std::string>&);
static int t_ssh(const std::vector<std::string>&);
static int t_ip(const std::vector<std::string>&);

static const std::map<std::string, std::pair<const char*, std::function<int(const std::vector<std::string>&)>>> TOOLS = {
    { "scan",{ "dt:scan <host> <port|a-b> [ms]  TCP scan", t_scan } },
    { "ping",{ "dt:ping <host> [count]          ICMP ping", t_ping } },
    { "dns",{ "dt:dns <domain>                 A/AAAA lookup", t_dns } },
    { "b64",{ "dt:b64 <e|d> <text>             Base64 encode/decode", t_b64 } },
    { "hash",{ "dt:hash sha256 <text|@file>     SHA-256 hash", t_hash } },
    { "whois",{ "dt:whois <domain>               Whois query", t_whois } },
    { "http",{ "dt:http <get|head> <url>        HTTP request", t_http } },
    { "ftp",{ "dt:ftp ls|get|put <url> ...     FTP transfer", t_ftp } },
    { "ssh",{ "dt:ssh <user@host> [cmd]        System OpenSSH", t_ssh } },
    { "ip",{ "dt:ip                            Public IP", t_ip } },
};

static void printBanner() {
    setColor(FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    conWrite(
        "    #########                          ##########                               ###                      ##\n"
        "    ##     ###   +####   ##    ##+         ##     ####:   ##+### ## ###+ ####   ###  ## ####    :####+   ##\n"
        "    ##     +##  ##   ##  x##  ###          ##    ##   ##  ###+   ##x  ###  x##  ###  ###  +##  ##   ##x  ##\n"
        "    ##     ### +########  ### ##           ##   ########+ ###    ##   ##x  .##  ###  ##    ##   #######  ##\n"
        "    ##    ###   ##   ##.   ####            ##    ##   ##  ###    ##   ##x  .##  ###  ##    ##  ##   ##x  ##\n"
        "    ######x      :###x      ##             ##     x###x   ###    ##   ##x  .##  ###  ##    ##   ###: ##  ##\n");
    setColor(FOREGROUND_INTENSITY);
    conWrite("==============================================================================\n");
    setColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    conWrite("  Dev Terminal v0.3 (Native C++)  |  dt:help for tools\n");
    setColor(FOREGROUND_INTENSITY);
    conWrite("==============================================================================\n\n");
    resetColor();
}

static void printPrompt() { setColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY); conWrite("DT> "); resetColor(); }

static std::vector<std::string> splitArgs(const std::string& s) {
    std::vector<std::string> out; std::string cur; bool quote = false;
    for (char c : s) {
        if (c == '"') { quote = !quote; continue; }
        if (!quote && c == ' ') { if (!cur.empty()) { out.push_back(cur); cur.clear(); } }
        else cur += c;
    }
    if (!cur.empty()) out.push_back(cur);
    return out;
}

static std::string readLine() {
    std::string line;
    printPrompt();
    while (true) {
        INPUT_RECORD rec; DWORD n;
        ReadConsoleInputA(g_conIn, &rec, 1, &n);
        if (rec.EventType != KEY_EVENT || !rec.Event.KeyEvent.bKeyDown) continue;
        const KEY_EVENT_RECORD& k = rec.Event.KeyEvent;
        char ch = k.uChar.AsciiChar;

        if (k.wVirtualKeyCode == VK_RETURN) {
            conWrite("\n");
            if (!line.empty()) { g_history.push_back(line); g_histIndex = (int)g_history.size(); }
            break;
        }
        else if (k.wVirtualKeyCode == VK_BACK) {
            if (!line.empty()) { line.pop_back(); conWrite("\b \b"); }
        }
        else if (k.wVirtualKeyCode == VK_UP) {
            if (g_histIndex > 0) {
                g_histIndex--;
                for (int i = 0; i < (int)line.length(); i++) conWrite("\b \b");
                line = g_history[g_histIndex]; conWrite(line);
            }
        }
        else if (k.wVirtualKeyCode == VK_DOWN) {
            if (g_histIndex < (int)g_history.size() - 1) {
                g_histIndex++;
                for (int i = 0; i < (int)line.length(); i++) conWrite("\b \b");
                line = g_history[g_histIndex]; conWrite(line);
            }
            else if (g_histIndex == (int)g_history.size() - 1) {
                g_histIndex++;
                for (int i = 0; i < (int)line.length(); i++) conWrite("\b \b");
                line.clear();
            }
        }
        else if (ch >= 32 && ch <= 126) {
            line += ch; conWrite(std::string(1, ch));
        }
    }
    return line;
}

static int err1(const char* msg) { printError(msg); return 1; }

static SOCKET tcpConnect(const std::string& host, unsigned short port, int timeoutMs = 800) {
    addrinfo hints = { 0 };
    addrinfo* res = nullptr;
    hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM;
    char ps[8]; snprintf(ps, sizeof(ps), "%u", port);
    if (getaddrinfo(host.c_str(), ps, &hints, &res) != 0) return INVALID_SOCKET;
    SOCKET s = INVALID_SOCKET;
    for (auto p = res; p; p = p->ai_next) {
        s = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (s == INVALID_SOCKET) continue;
        u_long nb = 1; ioctlsocket(s, FIONBIO, &nb);
        connect(s, p->ai_addr, (int)p->ai_addrlen);
        fd_set w; FD_ZERO(&w); FD_SET(s, &w);
        timeval tv = { timeoutMs / 1000, (timeoutMs % 1000) * 1000 };
        if (select(0, NULL, &w, NULL, &tv) > 0) {
            int e; int len = sizeof(e);
            if (getsockopt(s, SOL_SOCKET, SO_ERROR, (char*)&e, &len) == 0 && e == 0) {
                u_long bl = 0; ioctlsocket(s, FIONBIO, &bl); freeaddrinfo(res); return s;
            }
        }
        closesocket(s); s = INVALID_SOCKET;
    }
    freeaddrinfo(res); return INVALID_SOCKET;
}

static std::string sendRecv(SOCKET s, const std::string& data) {
    if (!data.empty()) send(s, data.data(), (int)data.size(), 0);
    std::string out; char buf[4096]; int n;
    timeval tv = { 3, 0 }; setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char*)&tv, sizeof(tv));
    while ((n = recv(s, buf, sizeof(buf) - 1, 0)) > 0) { buf[n] = 0; out += buf; if (n < (int)sizeof(buf) - 1) break; }
    return out;
}

static int t_scan(const std::vector<std::string>& a) {
    if (a.size() < 2) return err1("Usage: dt:scan <host> <port|a-b> [ms]");
    std::string host = a[0];
    int timeoutMs = a.size() > 2 ? atoi(a[2].c_str()) : 800;
    std::vector<int> ports;
    if (a[1].find('-') != std::string::npos) {
        auto p = a[1].find('-');
        for (int i = atoi(a[1].substr(0, p).c_str()); i <= atoi(a[1].substr(p + 1).c_str()); i++) ports.push_back(i);
    }
    else ports.push_back(atoi(a[1].c_str()));
    printInfo("Scanning " + host + " (" + std::to_string(ports.size()) + " ports)...");
    std::vector<int> open;
    for (size_t base = 0; base < ports.size(); base += 128) {
        struct Item { SOCKET s; int port; } items[128];
        size_t cnt = 0;
        for (size_t i = base; i < (std::min)(base + 128, ports.size()); i++) {
            SOCKET s = tcpConnect(host, (unsigned short)ports[i], timeoutMs);
            if (s != INVALID_SOCKET) items[cnt++] = { s, ports[i] };
        }
        for (size_t i = 0; i < cnt; i++) { open.push_back(items[i].port); closesocket(items[i].s); }
    }
    std::sort(open.begin(), open.end());
    for (int p : open) printInfo("  " + std::to_string(p) + "/tcp  open");
    if (open.empty()) conWrite("  (none)\n");
    return 0;
}

static int t_ping(const std::vector<std::string>& a) {
    if (a.empty()) return err1("Usage: dt:ping <host> [count]");
    int count = a.size() > 1 ? atoi(a[1].c_str()) : 4;
    addrinfo hints = { 0 }; addrinfo* res = nullptr;
    hints.ai_family = AF_INET;
    if (getaddrinfo(a[0].c_str(), NULL, &hints, &res) != 0) return err1("Resolve failed");
    ULONG ip = ((sockaddr_in*)res->ai_addr)->sin_addr.S_un.S_addr;
    freeaddrinfo(res);
    HANDLE h = IcmpCreateFile();
    if (h == INVALID_HANDLE_VALUE) return err1("IcmpCreateFile failed");
    char payload[32] = { 0 }; BYTE reply[1024];
    for (int i = 0; i < count; i++) {
        DWORD n = IcmpSendEcho(h, ip, payload, sizeof(payload), NULL, reply, sizeof(reply), 2000);
        if (n) {
            auto r = (PICMP_ECHO_REPLY)reply;
            printInfo("  from " + std::string(inet_ntoa(*(in_addr*)&r->Address)) + " time=" + std::to_string(r->RoundTripTime) + "ms TTL=" + std::to_string(r->Options.Ttl));
        }
        else printError("  timeout");
        if (i + 1 < count) Sleep(1000);
    }
    IcmpCloseHandle(h); return 0;
}

static int t_dns(const std::vector<std::string>& a) {
    if (a.empty()) return err1("Usage: dt:dns <domain>");
    bool any = false;
    for (WORD type : { (WORD)DNS_TYPE_A, (WORD)DNS_TYPE_AAAA }) {
        DNS_RECORDA* rec = nullptr;
        if (DnsQuery_A(a[0].c_str(), type, DNS_QUERY_STANDARD, NULL, (PDNS_RECORD*)&rec, NULL) == 0 && rec) {
            for (auto p = rec; p; p = p->pNext) {
                char buf[64] = { 0 };
                if (type == DNS_TYPE_A) { in_addr ia; ia.S_un.S_addr = p->Data.A.IpAddress; strncpy(buf, inet_ntoa(ia), sizeof(buf) - 1); }
                else if (type == DNS_TYPE_AAAA) {
                    sockaddr_in6 sa6 = { 0 }; sa6.sin6_family = AF_INET6;
                    memcpy(&sa6.sin6_addr, &p->Data.AAAA.Ip6Address, sizeof(sa6.sin6_addr));
                    DWORD sz = sizeof(buf);
                    if (WSAAddressToStringA((sockaddr*)&sa6, sizeof(sa6), NULL, buf, &sz) != 0) buf[0] = 0;
                }
                if (buf[0]) { printInfo("  " + std::string(buf)); any = true; }
            }
            DnsRecordListFree(rec, DnsFreeRecordList);
        }
    }
    if (!any) conWrite("  (no records)\n");
    return 0;
}

static const char B64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int t_b64(const std::vector<std::string>& a) {
    if (a.size() < 2) return err1("Usage: dt:b64 <e|d> <text>");
    const std::string& data = a[1];
    if (a[0] == "d") {
        auto val = [](char c) -> int {
            if (c >= 'A' && c <= 'Z') return c - 'A';
            if (c >= 'a' && c <= 'z') return c - 'a' + 26;
            if (c >= '0' && c <= '9') return c - '0' + 52;
            return c == '+' ? 62 : c == '/' ? 63 : -1;
            };
        std::string clean; for (char c : data) if (val(c) >= 0) clean += c;
        std::string out;
        for (size_t i = 0; i + 3 < clean.size(); i += 4) {
            int v0 = val(clean[i]), v1 = val(clean[i + 1]), v2 = val(clean[i + 2]), v3 = val(clean[i + 3]);
            out += (char)((v0 << 2) | (v1 >> 4)); out += (char)((v1 << 4) | (v2 >> 2)); out += (char)((v2 << 6) | v3);
        }
        conWrite(out + "\n");
    }
    else {
        std::string out;
        for (size_t i = 0; i < data.size(); i += 3) {
            uint32_t n = (uint32_t)(unsigned char)data[i] << 16;
            if (i + 1 < data.size()) n |= (uint32_t)(unsigned char)data[i + 1] << 8;
            if (i + 2 < data.size()) n |= (uint32_t)(unsigned char)data[i + 2];
            out += B64[(n >> 18) & 63]; out += B64[(n >> 12) & 63];
            out += i + 1 < data.size() ? B64[(n >> 6) & 63] : '=';
            out += i + 2 < data.size() ? B64[n & 63] : '=';
        }
        conWrite(out + "\n");
    }
    return 0;
}

struct Sha256 {
    uint32_t h[8] = { 0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19 };
    uint64_t len = 0; uint8_t buf[64]; size_t bufLen = 0;
    static uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }
    void block(const uint8_t* p) {
        static const uint32_t K[64] = {
            0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
            0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
            0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
            0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
            0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
            0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
            0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
            0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2 };
        uint32_t w[64];
        for (int i = 0; i < 16; i++) w[i] = (uint32_t)p[i * 4] << 24 | (uint32_t)p[i * 4 + 1] << 16 | (uint32_t)p[i * 4 + 2] << 8 | p[i * 4 + 3];
        for (int i = 16; i < 64; i++) {
            uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
            uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }
        uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
        for (int i = 0; i < 64; i++) {
            uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            uint32_t ch = (e & f) ^ (~e & g);
            uint32_t t1 = hh + S1 + ch + K[i] + w[i];
            uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t t2 = S0 + mj;
            hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
    }
    void update(const uint8_t* p, size_t n) {
        len += n * 8;
        while (n) {
            size_t take = (std::min)(n, 64 - bufLen);
            memcpy(buf + bufLen, p, take); bufLen += take; p += take; n -= take;
            if (bufLen == 64) { block(buf); bufLen = 0; }
        }
    }
    std::string hex() {
        uint8_t save[64]; size_t saveLen = bufLen; uint64_t saveBits = len;
        memcpy(save, buf, bufLen);
        buf[bufLen++] = 0x80;
        if (bufLen > 56) { while (bufLen < 64) buf[bufLen++] = 0; block(buf); bufLen = 0; }
        while (bufLen < 56) buf[bufLen++] = 0;
        for (int i = 7; i >= 0; i--) buf[bufLen++] = (uint8_t)(len >> (i * 8));
        block(buf);
        char out[65]; snprintf(out, sizeof(out), "%08x%08x%08x%08x%08x%08x%08x%08x", h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
        memcpy(buf, save, saveLen); bufLen = saveLen; len = saveBits;
        return out;
    }
};

static int t_hash(const std::vector<std::string>& a) {
    if (a.size() < 2) return err1("Usage: dt:hash sha256 <text|@file>");
    if (a[0] != "sha256") return err1("Only sha256 supported");
    std::string data;
    if (a[1].rfind("@", 0) == 0) {
        FILE* f = fopen(a[1].c_str() + 1, "rb");
        if (!f) return err1("Cannot open file");
        Sha256 s; char buf[8192]; size_t n;
        while ((n = fread(buf, 1, sizeof(buf), f))) s.update((uint8_t*)buf, n);
        fclose(f); conWrite(s.hex() + "\n");
    }
    else {
        Sha256 s; s.update((uint8_t*)a[1].data(), a[1].size());
        conWrite(s.hex() + "\n");
    }
    return 0;
}

static std::string whoisQuery(const std::string& server, const std::string& domain) {
    SOCKET s = tcpConnect(server, 43, 5000);
    if (s == INVALID_SOCKET) return "(Connect failed)";
    std::string r = sendRecv(s, domain + "\r\n");
    closesocket(s);
    return r;
}

static int t_whois(const std::vector<std::string>& a) {
    if (a.empty()) return err1("Usage: dt:whois <domain>");
    std::string resp = whoisQuery("whois.iana.org", a[0]);
    std::string refer;
    size_t pos = 0;
    while ((pos = resp.find("refer:", pos)) != std::string::npos) {
        size_t e = resp.find('\n', pos);
        refer = resp.substr(pos + 6, e == std::string::npos ? e : e - pos - 6);
        refer.erase(0, refer.find_first_not_of(" \t"));
        refer.erase(refer.find_last_not_of(" \t\r") + 1);
        break;
    }
    conWrite(refer.empty() ? resp : whoisQuery(refer, a[0]));
    return 0;
}

static int t_http(const std::vector<std::string>& a) {
    if (a.size() < 2) return err1("Usage: dt:http <get|head> <url>");
    std::string url = a[1];
    if (url.rfind("http://", 0) != 0) return err1("Only http:// supported");
    bool isHead = a[0] == "head";
    std::string rest = url.substr(7), host, path = "/";
    auto slash = rest.find('/');
    if (slash == std::string::npos) host = rest;
    else { host = rest.substr(0, slash); path = rest.substr(slash); }
    unsigned short port = 80;
    if (auto c = host.find(':'); c != std::string::npos) { port = (unsigned short)atoi(host.substr(c + 1).c_str()); host = host.substr(0, c); }
    SOCKET s = tcpConnect(host, port, 5000);
    if (s == INVALID_SOCKET) return err1("Connect failed");
    std::string req = std::string(isHead ? "HEAD " : "GET ") + path + " HTTP/1.0\r\nHost: " + host + "\r\nUser-Agent: DevTerminal/0.3\r\nConnection: close\r\n\r\n";
    send(s, req.data(), (int)req.size(), 0);
    std::string resp; char buf[4096]; int n;
    while ((n = recv(s, buf, sizeof(buf) - 1, 0)) > 0) { buf[n] = 0; resp += buf; }
    closesocket(s);
    auto sep = resp.find("\r\n\r\n");
    conWrite(resp.substr(0, sep) + "\n");
    if (!isHead && sep != std::string::npos) conWrite(resp.substr(sep + 4) + "\n");
    return 0;
}

static int t_ftp(const std::vector<std::string>& a) {
    if (a.size() < 2) return err1("Usage: dt:ftp ls|get|put <url> [file] [user pass]");
    std::string u = a[1];
    if (u.rfind("ftp://", 0) != 0) return err1("URL must start with ftp://");
    std::string rest = u.substr(6), host, path = "/";
    auto slash = rest.find('/');
    if (slash == std::string::npos) host = rest; else { host = rest.substr(0, slash); path = rest.substr(slash); }
    unsigned short port = 21;
    if (auto c = host.find(':'); c != std::string::npos) { port = (unsigned short)atoi(host.substr(c + 1).c_str()); host = host.substr(0, c); }
    std::string op0 = a[0];
    int credIdx = (op0 == "ls") ? 2 : 3;
    std::string user = a.size() >= (size_t)(credIdx + 2) ? a[credIdx] : "anonymous";
    std::string pass = a.size() >= (size_t)(credIdx + 2) ? a[credIdx + 1] : "dev@terminal";
    SOCKET ctrl = tcpConnect(host, port, 5000);
    if (ctrl == INVALID_SOCKET) return err1("Connect failed");
    std::string r;
    auto ftpReply = [&](const std::string& cmd) {
        if (!cmd.empty()) send(ctrl, cmd.data(), (int)cmd.size(), 0);
        r.clear(); char buf[1024]; int n;
        while ((n = recv(ctrl, buf, sizeof(buf) - 1, 0)) > 0) {
            buf[n] = 0; r += buf;
            if (r.size() >= 4 && r[3] == ' ') break;
        }
        };
    ftpReply("");
    ftpReply("USER " + user + "\r\n");
    ftpReply("PASS " + pass + "\r\n");
    ftpReply("TYPE I\r\n");
    if (r[0] == '5') { printError("Auth failed"); closesocket(ctrl); return 1; }
    ftpReply("PASV\r\n");
    auto lp = r.find('('), rp = r.find(')');
    if (lp == std::string::npos || rp == std::string::npos) { closesocket(ctrl); return err1("PASV not supported"); }
    int h1, h2, h3, h4, p1, p2;
    sscanf(r.substr(lp + 1, rp - lp - 1).c_str(), "%d,%d,%d,%d,%d,%d", &h1, &h2, &h3, &h4, &p1, &p2);
    char dataIp[32]; snprintf(dataIp, sizeof(dataIp), "%d.%d.%d.%d", h1, h2, h3, h4);
    SOCKET data = tcpConnect(dataIp, (unsigned short)(p1 * 256 + p2), 5000);
    if (data == INVALID_SOCKET) { closesocket(ctrl); return err1("Data connect failed"); }
    if (op0 == "ls") {
        ftpReply("LIST " + path + "\r\n");
        char buf[4096]; int n;
        while ((n = recv(data, buf, sizeof(buf) - 1, 0)) > 0) { buf[n] = 0; conWrite(buf); }
    }
    else if (op0 == "get") {
        if (a.size() < 3) { closesocket(data); closesocket(ctrl); return err1("Missing local file"); }
        ftpReply("RETR " + path + "\r\n");
        FILE* f = fopen(a[2].c_str(), "wb");
        if (!f) { closesocket(data); closesocket(ctrl); return err1("Cannot open file"); }
        char buf[16384]; int n;
        while ((n = recv(data, buf, sizeof(buf), 0)) > 0) fwrite(buf, 1, n, f);
        fclose(f); printInfo("Downloaded -> " + a[2]);
    }
    else if (op0 == "put") {
        if (a.size() < 3) { closesocket(data); closesocket(ctrl); return err1("Missing local file"); }
        FILE* f = fopen(a[1].c_str(), "rb");
        if (!f) { closesocket(data); closesocket(ctrl); return err1("Cannot open file"); }
        ftpReply("STOR " + path + "\r\n");
        char buf[16384]; size_t n;
        while ((n = fread(buf, 1, sizeof(buf), f))) send(data, buf, (int)n, 0);
        fclose(f); printInfo("Uploaded -> " + path);
    }
    else { closesocket(data); closesocket(ctrl); return err1("Unknown subcommand"); }
    closesocket(data);
    ftpReply("QUIT\r\n");
    closesocket(ctrl);
    return 0;
}

static int t_ssh(const std::vector<std::string>& a) {
    if (a.empty()) return err1("Usage: dt:ssh <user@host> [cmd]");
    std::string cmd = "ssh ";
    for (auto& x : a) { cmd += x; cmd += " "; }
    system(cmd.c_str());
    return 0;
}

static int t_ip(const std::vector<std::string>&) {
    SOCKET s = tcpConnect("api.ipify.org", 80, 5000);
    if (s == INVALID_SOCKET) return err1("Query failed");
    std::string r = sendRecv(s, "GET / HTTP/1.0\r\nHost: api.ipify.org\r\nConnection: close\r\n\r\n");
    closesocket(s);
    auto sep = r.find("\r\n\r\n");
    conWrite(sep == std::string::npos ? r : r.substr(sep + 4));
    return 0;
}

int main() {
    SetConsoleOutputCP(CP_UTF8);
    g_conOut = GetStdHandle(STD_OUTPUT_HANDLE);
    g_conIn = GetStdHandle(STD_INPUT_HANDLE);

    WSADATA ws; WSAStartup(MAKEWORD(2, 2), &ws);

    printBanner();

    while (true) {
        std::string line = readLine();
        if (line.empty()) continue;

        auto args = splitArgs(line);
        std::string cmd = args[0];
        std::string tool;

        if (cmd.rfind("dt:", 0) == 0) {
            tool = cmd.substr(3);
        }
        else {
            tool = cmd;
        }

        std::vector<std::string> toolArgs(args.begin() + 1, args.end());

        if (tool == "cls" || tool == "clear") {
            system("cls");
            printBanner();
            continue;
        }

        if (tool == "help") {
            conWrite("Built-in tools:\n");
            for (auto& [name, info] : TOOLS) {
                conWrite("  " + std::string(info.first) + "\n");
            }
        }
        else if (tool == "exit") {
            break;
        }
        else {
            auto it = TOOLS.find(tool);
            if (it != TOOLS.end()) {
                it->second.second(toolArgs);
            }
            else {
                printError("Unknown tool: " + tool);
            }
        }
    }

    WSACleanup();
    return 0;
}
