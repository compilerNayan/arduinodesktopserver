#ifndef HTTPTCPSERVER_H
#define HTTPTCPSERVER_H

#include "IServer.h"
#include "IHttpRequest.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>
#include <iostream>
#include <sstream>
#include <vector>
#include <random>
#include <iomanip>
#include <map>

/**
 * Sender details structure to store client connection information
 */
struct SenderDetails {
    Int socket;
    StdString ipAddress;
    UInt port;
    
    SenderDetails() : socket(-1), ipAddress(""), port(0) {}
    SenderDetails(Int sock, CStdString& ip, CUInt p) : socket(sock), ipAddress(ip), port(p) {}
};

/**
 * HTTP TCP Server implementation of IServer interface
 * Header-only implementation using standard TCP sockets
 */
/* @ServerImpl("http tcp server") */
class HttpTcpServer : public IServer {
    Private UInt port_;
    Private Int serverSocket_;
    Private Bool running_;
    Private StdString ipAddress_;
    Private StdString lastClientIp_;
    Private UInt lastClientPort_;
    Private ULong receivedMessageCount_;
    Private ULong sentMessageCount_;
    Private UInt maxMessageSize_;
    Private UInt receiveTimeout_;
    Private StdMap<StdString, SenderDetails> requestSenderMap_;

    Private StdString GenerateGuid() {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 15);
        std::uniform_int_distribution<> dis2(8, 11);
        
        std::ostringstream oss;
        oss << std::hex;
        
        // Generate UUID v4 format: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
        for (Size i = 0; i < 8; i++) {
            oss << dis(gen);
        }
        oss << "-";
        for (Size i = 0; i < 4; i++) {
            oss << dis(gen);
        }
        oss << "-4";
        for (Size i = 0; i < 3; i++) {
            oss << dis(gen);
        }
        oss << "-";
        oss << dis2(gen);
        for (Size i = 0; i < 3; i++) {
            oss << dis(gen);
        }
        oss << "-";
        for (Size i = 0; i < 12; i++) {
            oss << dis(gen);
        }
        
        return oss.str();
    }

    Private Void CloseSocket(Int& socket) {
        if (socket >= 0) {
            close(socket);
            socket = -1;
        }
    }

    Private Void SendHttpResponse(Int clientSocket, CStdString& request) {
        // Parse the request to extract method and path
        std::istringstream requestStream(request);
        StdString method, path, version;
        requestStream >> method >> path >> version;
        
        // Build HTTP response
        std::ostringstream response;
        response << "HTTP/1.1 200 OK\r\n";
        response << "Content-Type: text/plain\r\n";
        response << "Connection: close\r\n";
        response << "\r\n";
        response << "Request received successfully!\n";
        response << "Method: " << method << "\n";
        response << "Path: " << path << "\n";
        response << "Full Request:\n" << request;
        
        StdString responseStr = response.str();
        send(clientSocket, responseStr.c_str(), responseStr.length(), 0);
        sentMessageCount_++;
    }

    Public HttpTcpServer() 
        : port_(DEFAULT_SERVER_PORT), serverSocket_(-1), running_(false),
          ipAddress_("0.0.0.0"), lastClientIp_(""), lastClientPort_(0),
          receivedMessageCount_(0), sentMessageCount_(0),
          maxMessageSize_(88192), receiveTimeout_(0) {
    }

    Public HttpTcpServer(CUInt port) 
        : port_(port), serverSocket_(-1), running_(false),
          ipAddress_("0.0.0.0"), lastClientIp_(""), lastClientPort_(0),
          receivedMessageCount_(0), sentMessageCount_(0),
          maxMessageSize_(88192), receiveTimeout_(0) {
    }

    Public Virtual ~HttpTcpServer() {
        Stop();
    }

    Public Virtual Bool Start(CUInt port = DEFAULT_SERVER_PORT) override {
        
        if (running_) {
            return false;
        }

        port_ = port;
        
        // Create socket
        serverSocket_ = socket(AF_INET, SOCK_STREAM, 0);
        if (serverSocket_ < 0) {
            return false;
        }
        
        // Set socket option to reuse address
        Int opt = 1;
        if (setsockopt(serverSocket_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
            CloseSocket(serverSocket_);
            return false;
        }
        
        // Bind socket to address
        sockaddr_in serverAddress{};
        serverAddress.sin_family = AF_INET;
        
        // Set IP address
        if (ipAddress_ == "0.0.0.0") {
            serverAddress.sin_addr.s_addr = INADDR_ANY;
        } else {
            if (inet_aton(ipAddress_.c_str(), &serverAddress.sin_addr) == 0) {
                CloseSocket(serverSocket_);
                return false;
            }
        }
        
        serverAddress.sin_port = htons(static_cast<uint16_t>(port_));
        
        if (bind(serverSocket_, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0) {
            CloseSocket(serverSocket_);
            return false;
        }
        
        // Listen for connections
        if (listen(serverSocket_, 5) < 0) {
            CloseSocket(serverSocket_);
            return false;
        }
        
        running_ = true;
        return true;
    }

    Public Virtual Void Stop() override {
        if (running_) {
            CloseSocket(serverSocket_);
            running_ = false;
        }
    }

    Public Virtual Bool IsRunning() const override {
        return running_;
    }

    Public Virtual UInt GetPort() const override {
        return port_;
    }

    Public Virtual StdString GetIpAddress() const override {
        return ipAddress_;
    }

    Public Virtual Bool SetIpAddress(CStdString& ip) override {
        if (running_) {
            return false;
        }
        ipAddress_ = ip;
        return true;
    }

    Public Virtual IHttpRequestPtr ReceiveMessage() override {
        if (!running_ || serverSocket_ < 0) {
            return nullptr;
        }
        
        // Accept a client connection
        sockaddr_in clientAddress{};
        socklen_t clientAddressLength = sizeof(clientAddress);
        
        Int clientSocket = accept(serverSocket_, (struct sockaddr*)&clientAddress, &clientAddressLength);
        if (clientSocket < 0) {
            return nullptr;
        }
        
        // Store client information
        Char clientIP[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &clientAddress.sin_addr, clientIP, INET_ADDRSTRLEN);
        lastClientIp_ = StdString(clientIP);
        lastClientPort_ = ntohs(clientAddress.sin_port);
        
        // Receive HTTP request - read headers first
        // Use dynamic buffer based on maxMessageSize_ (default allows up to 100MB)
        Size bufferSize = maxMessageSize_ > 0 ? maxMessageSize_ : 104857600; // 100MB default max
        StdVector<Char> buffer(bufferSize, 0);
        Size totalReceived = 0;
        
        // Read until we get the headers (double CRLF)
        while (true) {
            Size remainingSpace = bufferSize - totalReceived - 1;
            if (remainingSpace == 0) {
                break; // Buffer full
            }
            
            ssize_t bytesReceived = recv(clientSocket, buffer.data() + totalReceived, 
                                        remainingSpace, 0);
            if (bytesReceived <= 0) {
                if (totalReceived == 0) {
                    CloseSocket(clientSocket);
                    return nullptr;
                }
                break;
            }
            
            totalReceived += bytesReceived;
            buffer[totalReceived] = '\0';
            
            // Check if we've received the headers (look for double CRLF)
            StdString currentData(buffer.data(), totalReceived);
            Size headerEnd = currentData.find("\r\n\r\n");
            if (headerEnd == StdString::npos) {
                headerEnd = currentData.find("\n\n");
            }
            
            if (headerEnd != StdString::npos) {
                // Headers received, check for Content-Length
                Size contentLengthPos = currentData.find("Content-Length:");
                if (contentLengthPos != StdString::npos) {
                    // Extract Content-Length value
                    Size valueStart = currentData.find(':', contentLengthPos) + 1;
                    Size valueEnd = currentData.find("\r\n", valueStart);
                    if (valueEnd == StdString::npos) {
                        valueEnd = currentData.find('\n', valueStart);
                    }
                    
                    StdString contentLengthStr = currentData.substr(valueStart, valueEnd - valueStart);
                    // Trim whitespace
                    contentLengthStr.erase(0, contentLengthStr.find_first_not_of(" \t"));
                    contentLengthStr.erase(contentLengthStr.find_last_not_of(" \t") + 1);
                    
                    ULong contentLength = std::stoull(contentLengthStr);
                    Size bodyStart = headerEnd + 4; // Skip double CRLF
                    Size bodyReceived = totalReceived - bodyStart;
                    
                    // Ensure we have enough buffer space for the full body
                    Size requiredSize = bodyStart + contentLength;
                    if (requiredSize > bufferSize) {
                        // Buffer too small, resize if possible (up to maxMessageSize_)
                        if (requiredSize <= maxMessageSize_ || maxMessageSize_ == 0) {
                            bufferSize = requiredSize;
                            buffer.resize(bufferSize);
                        } else {
                            // Content-Length exceeds maxMessageSize_, truncate
                            contentLength = maxMessageSize_ - bodyStart;
                        }
                    }
                    
                    // Read remaining body if needed
                    while (bodyReceived < contentLength && 
                           totalReceived < bufferSize - 1) {
                        Size remaining = bufferSize - totalReceived - 1;
                        ssize_t moreBytes = recv(clientSocket, buffer.data() + totalReceived, 
                                                remaining, 0);
                        if (moreBytes <= 0) break;
                        totalReceived += moreBytes;
                        bodyReceived = totalReceived - bodyStart;
                    }
                }
                break;
            }
            
            // Prevent buffer overflow
            if (totalReceived >= bufferSize - 1) {
                break;
            }
        }
        
        StdString requestString(buffer.data(), totalReceived);
        
        // Generate GUID for this request
        StdString requestId = GenerateGuid();
        
        // Store sender details against the GUID
        SenderDetails senderDetails(clientSocket, lastClientIp_, lastClientPort_);
        requestSenderMap_[requestId] = senderDetails;
        
        receivedMessageCount_++;
        
        // Parse and return IHttpRequest with request ID
        return IHttpRequest::GetRequest(requestId, requestString);
    }

    Public Virtual Bool SendMessage(CStdString& requestId, CStdString& message) override {
        if (!running_ || serverSocket_ < 0) {
            return false;
        }
        
        // Look up sender details from the map using requestId
        auto it = requestSenderMap_.find(StdString(requestId));
        if (it == requestSenderMap_.end()) {
            return false; // Request ID not found
        }
        
        SenderDetails& senderDetails = it->second;
        
        // Check if socket is valid
        if (senderDetails.socket < 0) {
            return false;
        }
        
        // Send the message using the stored socket
        ssize_t bytesSent = send(senderDetails.socket, message.c_str(), message.length(), 0);
        if (bytesSent < 0) {
            return false;
        }
        
        // Close the socket after sending
        CloseSocket(senderDetails.socket);
        
        // Remove the entry from the map after sending
        requestSenderMap_.erase(it);
        
        sentMessageCount_++;
        return true;
    }

    Public Virtual StdString GetLastClientIp() const override {
        return lastClientIp_;
    }

    Public Virtual UInt GetLastClientPort() const override {
        return lastClientPort_;
    }

    Public Virtual ULong GetReceivedMessageCount() const override {
        return receivedMessageCount_;
    }

    Public Virtual ULong GetSentMessageCount() const override {
        return sentMessageCount_;
    }

    Public Virtual Void ResetStatistics() override {
        receivedMessageCount_ = 0;
        sentMessageCount_ = 0;
    }

    Public Virtual UInt GetMaxMessageSize() const override {
        return maxMessageSize_;
    }

    Public Virtual Bool SetMaxMessageSize(Size size) override {
        if (running_) {
            return false;
        }
        maxMessageSize_ = static_cast<UInt>(size);
        return true;
    }

    Public Virtual UInt GetReceiveTimeout() const override {
        return receiveTimeout_;
    }

    Public Virtual Bool SetReceiveTimeout(CUInt timeoutMs) override {
        receiveTimeout_ = timeoutMs;
        if (serverSocket_ >= 0) {
            struct timeval tv;
            tv.tv_sec = timeoutMs / 1000;
            tv.tv_usec = (timeoutMs % 1000) * 1000;
            if (setsockopt(serverSocket_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
                return false;
            }
        }
        return true;
    }

    Public Virtual ServerType GetServerType() const override {
        return ServerType::TCP;
    }

    Public Virtual StdString GetId() const override {
        return StdString("arduinotcpserver");
    }
};

#endif // HTTPTCPSERVER_H

