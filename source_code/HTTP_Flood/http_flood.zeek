# Load the necessary scripts for HTTP and logging
@load base/protocols/http

# Define constants for the threshold and time window
const flood_threshold = 100;  # Number of requests considered as a flood
const time_window = 1min;     # Time window for monitoring requests

# Global table to keep track of request counts per IP address
global request_count: table[addr] of count &default=0;

# Event handler for new HTTP requests
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
