/**
 * Script to validate potential Cross-Site WebSocket Hijacking vulnerability. 
 * 
 * According to RFC 6455, section 10.2 Origin Considerations:
 * 
 * "Servers that are not intended to process input from any web page but
 * only for certain sites SHOULD verify the |Origin| field is an origin
 * they expect.  If the origin indicated is unacceptable to the server,
 * then it SHOULD respond to the WebSocket handshake with a reply
 * containing HTTP 403 Forbidden status code."
 * 
 * Which means we can try to repeat WebSocket HTTP Upgrade request with 
 * a modified Origin header and raise an alert if it was accepted. 
 * 
 * Note: Run ajax spider before scan in order to trigger opening WebSockets.
 * Note: Active scripts are initially disabled, right click the script to enable it.
 * 
 * Author: Piotr Furman <piotr.furman at motorolasolutions.com>
 */

var Base64 = Java.type("java.util.Base64")
var Random = Java.type("java.util.Random")
var String = Java.type("java.lang.String")
var ByteArray = Java.type("byte[]")

var RISK = 3
var CONFIDENCE = 2
var TITLE = "Cross-Site WebSocket Hijacking"
var DESCRIPTION = "Server accepted WebSocket connection through HTTP Upgrade request with modified Origin header."
var SOLUTION = "Validate Origin header on WebSocket connection handshake, to ensure only specified origins are allowed to connect. Also, WebSocket handshake should use random tokens, similar to anti CSRF tokens."
var REFERENCE = "https://tools.ietf.org/html/rfc6455#section-10.2"
var OTHER = "See also https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking or https://christian-schneider.net/CrossSiteWebSocketHijacking.html"
var CWEID = 346 // CWE-346: Origin Validation Error, http://cwe.mitre.org/data/definitions/346.html
var WASCID = 9 // WASC-9 Cross Site Request Forgery, http://projects.webappsec.org/w/page/13246919/Cross%20Site%20Request%20Forgery

function scanNode(as, msg) {
    var target = msg.getRequestHeader().getURI().toString()

    // check if this is a WebSocket HTTP Upgrade request
    // request message should include also "Connection: Upgrade" header but let's skip it for now, and switch to msg.isWebSocketUpgrade() if https://github.com/zaproxy/zaproxy/pull/6508 was merged
    var upgrade_header = msg.getRequestHeader().getHeader("Upgrade")
    if (!upgrade_header || upgrade_header.toLowerCase() !== "websocket") {
        print("Cross-Site WebSocket Hijacking scan skipped for url=" + target + ", is not a WebSocket upgrade request")
        return
    }

    print("Cross-Site WebSocket Hijacking scan started for url=" + target)
    msg = msg.cloneRequest()
    
    // set random Sec-WebSocket-Key 
    var randomBytes = new ByteArray(16)
    new Random().nextBytes(randomBytes)
    var secWsKey = new String(Base64.getEncoder().encode(randomBytes))
    msg.getRequestHeader().setHeader("Sec-WebSocket-Key", secWsKey)

    // set Origin header using custom domain, .example is a reserved TLD in RFC 2606 so it should not match domain name of a scanned service
    msg.getRequestHeader().setHeader("Origin", "https://cswsh.example")

    as.sendAndReceive(msg, true, false)

    if (as.isStop()) {
        return
    }
    
    var responseStatus = msg.getResponseHeader().getStatusCode()
    if (responseStatus == 101) {
        // should not have accepted connection with different origin
        print("Cross-Site WebSocket Hijacking vulnerability found, sending alert for url=" + target)
        as.newAlert()
          .setRisk(RISK)
          .setConfidence(CONFIDENCE)
          .setName(TITLE)
          .setDescription(DESCRIPTION)
          .setParam(target)
          .setAttack('')
          .setEvidence(msg.getResponseHeader().getPrimeHeader())
          .setOtherInfo(OTHER)
          .setSolution(SOLUTION)
          .setReference(REFERENCE)
          .setCweId(CWEID)
          .setWascId(WASCID)
          .setMessage(msg)
          .raise()
     }
}
