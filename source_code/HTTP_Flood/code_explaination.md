# Zeek Script Explanation

## Overview

The provided Zeek script is designed to detect HTTP flood attacks within a network. It monitors HTTP requests and generates an alert when the number of requests from a single IP address exceeds a specified threshold within a given time window.

# Script Breakdown
### 1. Loading Frameworks
The script begins by loading the necessary HTTP framework, which is essential for monitoring HTTP requests.

```

@load base/protocols/http
```
### 2. Define Constants
The script defines constants for the flood detection threshold and the time window. These values determine the criteria for identifying an HTTP flood attack.
```
const flood_threshold = 100;  # Number of requests considered as a flood
const time_window = 1min;     # Time window for monitoring requests
```
### 3. Global Table Declaration

A global table is declared to keep track of the number of HTTP requests made by each IP address. This table is initialized with a default value of 0.

```
global request_count: table[addr] of count &default=0;
```
### 4. HTTP Request Event Handler

The http_request event handler is triggered whenever a new HTTP request is observed. It processes each request, updates the count, and checks for potential flood attacks.

```
event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string) {
    local client_ip = c$id$orig_h;

    # Increment the request count for the client IP
    request_count[client_ip] += 1;

    # Schedule a timer to reset the count after the time window
    when (network_time() + time_window) {
        request_count[client_ip] = 0;
    }

    # Check if the request count exceeds the flood threshold
    if (request_count[client_ip] > flood_threshold) {
        # Raise an alert for HTTP flood detection
        print fmt("HTTP flood detected from %s: %d requests in the last %d seconds", client_ip, request_count[client_ip], time_window);
        Log::write(HTTP::LOG, "HTTP flood detected from %s: %d requests in the last %d seconds", client_ip, request_count[client_ip], time_window);
    }
}
```
#### Explanation of the Event Handler
##### Extract Client IP:

The client's IP address (client_ip) is extracted from the connection object.
##### Increment Request Count:

The request count for the client IP is incremented by 1.
##### Reset Timer:

A timer (when) is scheduled to reset the request count for the client IP after the specified time window (time_window).
##### Check Flood Threshold:

If the request count exceeds the flood threshold, an alert is printed and logged to indicate a potential HTTP flood attack.
### 5. Conclusion

This Zeek script provides a mechanism for detecting HTTP flood attacks within a network by monitoring the frequency of HTTP requests from individual IP addresses and generating alerts when suspicious activity is detected. This approach helps in identifying and mitigating potential denial-of-service (DoS) attacks targeting web servers.