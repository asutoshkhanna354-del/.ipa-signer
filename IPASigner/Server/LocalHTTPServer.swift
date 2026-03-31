import Foundation
import Network

// MARK: - Local HTTP Server

/// A lightweight HTTP server built on Network.framework (no third-party dependency)
/// Used to serve the signed IPA and OTA manifest.plist for local installation
class LocalHTTPServer {

    // MARK: - Properties

    private var listener: NWListener?
    private var connections: [NWConnection] = []
    private var ipaURL: URL?
    private var manifestURL: URL?
    private(set) var port: UInt16 = 0
    private(set) var isRunning = false

    // MARK: - Start Server

    /// Start the HTTP server
    /// - Parameters:
    ///   - ipaURL: Path to the signed IPA file
    ///   - manifestURL: Path to the generated manifest.plist
    func start(ipaURL: URL, manifestURL: URL) throws {
        self.ipaURL = ipaURL
        self.manifestURL = manifestURL

        let params = NWParameters.tcp
        listener = try NWListener(using: params, on: .any)

        listener?.newConnectionHandler = { [weak self] connection in
            self?.handleConnection(connection)
        }

        listener?.stateUpdateHandler = { [weak self] state in
            switch state {
            case .ready:
                if let port = self?.listener?.port?.rawValue {
                    self?.port = port
                    self?.isRunning = true
                    LogManager.shared.log("HTTP server started on port \(port)")
                }
            case .failed(let error):
                LogManager.shared.log("HTTP server failed: \(error)")
                self?.isRunning = false
            default:
                break
            }
        }

        listener?.start(queue: .global(qos: .userInitiated))

        // Wait briefly for server to bind
        Thread.sleep(forTimeInterval: 0.3)
    }

    /// Stop the server and close all connections
    func stop() {
        connections.forEach { $0.cancel() }
        connections.removeAll()
        listener?.cancel()
        listener = nil
        isRunning = false
        LogManager.shared.log("HTTP server stopped")
    }

    // MARK: - Connection Handling

    private func handleConnection(_ connection: NWConnection) {
        connections.append(connection)

        connection.stateUpdateHandler = { [weak self] state in
            if case .cancelled = state {
                self?.connections.removeAll { $0 === connection }
            }
        }

        connection.start(queue: .global(qos: .userInitiated))
        receiveRequest(connection: connection)
    }

    private func receiveRequest(connection: NWConnection) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] data, _, isComplete, error in
            guard let self = self, let data = data, !data.isEmpty else {
                connection.cancel()
                return
            }

            let request = String(data: data, encoding: .utf8) ?? ""
            self.handleHTTPRequest(request, connection: connection)
        }
    }

    private func handleHTTPRequest(_ request: String, connection: NWConnection) {
        // Parse the request line (e.g. "GET /manifest.plist HTTP/1.1")
        let lines = request.components(separatedBy: "\r\n")
        guard let requestLine = lines.first else {
            sendResponse(statusCode: 400, body: Data(), contentType: "text/plain", connection: connection)
            return
        }

        let parts = requestLine.components(separatedBy: " ")
        guard parts.count >= 2 else {
            sendResponse(statusCode: 400, body: Data(), contentType: "text/plain", connection: connection)
            return
        }

        let path = parts[1]
        LogManager.shared.log("HTTP \(parts[0]) \(path)")

        switch path {
        case "/manifest.plist":
            serveFile(at: manifestURL, contentType: "text/xml", connection: connection)

        case "/app.ipa":
            serveFile(at: ipaURL, contentType: "application/octet-stream", connection: connection)

        case "/":
            let html = """
            <!DOCTYPE html>
            <html>
            <head><title>IPA Installer</title></head>
            <body>
            <h2>IPA Signer - OTA Install</h2>
            <a href="itms-services://?action=download-manifest&url=https://127.0.0.1:\(port)/manifest.plist">
            Install App
            </a>
            </body>
            </html>
            """
            sendResponse(
                statusCode: 200,
                body: Data(html.utf8),
                contentType: "text/html",
                connection: connection
            )

        default:
            sendResponse(statusCode: 404, body: Data("Not Found".utf8), contentType: "text/plain", connection: connection)
        }
    }

    private func serveFile(at url: URL?, contentType: String, connection: NWConnection) {
        guard let url = url, let data = try? Data(contentsOf: url) else {
            sendResponse(statusCode: 404, body: Data("File not found".utf8), contentType: "text/plain", connection: connection)
            return
        }
        sendResponse(statusCode: 200, body: data, contentType: contentType, connection: connection)
    }

    private func sendResponse(statusCode: Int, body: Data, contentType: String, connection: NWConnection) {
        let statusText: String
        switch statusCode {
        case 200: statusText = "OK"
        case 404: statusText = "Not Found"
        default:  statusText = "Error"
        }

        let header = """
        HTTP/1.1 \(statusCode) \(statusText)\r
        Content-Type: \(contentType)\r
        Content-Length: \(body.count)\r
        Connection: close\r
        \r

        """

        var response = Data(header.utf8)
        response.append(body)

        connection.send(content: response, completion: .contentProcessed { _ in
            connection.cancel()
        })
    }
}
