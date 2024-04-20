# Zeek Script Explanation

## Overview

The provided Zeek script is designed to detect port scanning activity within a network. It utilizes the SumStats framework and the Notice framework to observe connection attempts and generate notices when a threshold of connection attempts is exceeded.

## Script Breakdown

### 1. Loading Frameworks

The script begins by loading the SumStats and Notice frameworks, which are essential for observing and reporting connection attempts.

```zeek
@load base/frameworks/sumstats
@load base/frameworks/notice
```

### 2. Module Definition
The script defines a module named Scancheck, which contains the functionality for detecting port scanning activity.

```
module Scancheck;
```
### 3. Export Declarations
Inside the Scancheck module, there are export declarations for defining new types and constants.\
```
export {
    redef enum Notice::Type += {
        Port_Scan_Detect,
    };

    const threshold = 10.0 &redef;
}
```
The Port_Scan_Detect notice type is added to the Notice::Type enumeration to categorize port scanning notices.
A constant named threshold is defined to specify the threshold for detecting port scanning activity. This value is set to 10.0 by default.
### 4. Event Handlers
connection_attempt Event
The connection_attempt event handler is triggered whenever a connection attempt occurs. It observes the connection attempt and increments the observation count for the corresponding connection parameters using the SumStats::observe function.

```
event connection_attempt(c: connection)
{
    SumStats::observe("conn attempted",
                      SumStats::Key($host = c$id$orig_h, $str = cat(c$id$resp_h)),
                      SumStats::Observation($num = 1));
}
```
### 5. Initialization Event
The zeek_init event handler is triggered during Zeek initialization. It sets up a SumStats reducer and creates a SumStats object to monitor connection attempts over a specified time period.

```
event zeek_init() &priority=5 {
    local r1 = SumStats::Reducer($stream = "conn attempted", $apply = set(SumStats::SUM));
    SumStats::create([
        $name = "finding port scanners",
        $epoch = 5min,
        $reducers = set(r1),
        $threshold = threshold,
        $threshold_val(key: SumStats::Key, result: SumStats::Result) =
        {
            return result["conn attempted"]$sum;
        },
        $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
        {
            local msg = fmt("%s attempted %.0f or more connections", key$host, result["conn attempted"]$sum);
            NOTICE([
                $note = Port_Scan_Detect,
                $msg = msg,
                $src = key$host,
                $dst = to_addr(key$str),
                $identifier = cat(key$host)
            ]);
        }
    ]);
}
```

The zeek_init event handler initializes a SumStats reducer to sum the observations of connection attempts.
It creates a SumStats object named "finding port scanners" with the specified parameters:
$epoch: The time period over which to monitor connection attempts (set to 5 minutes).
$reducers: A set containing the defined reducer.
$threshold: The threshold value for detecting port scanning activity (defined by the threshold constant).
$threshold_val: A function that calculates the sum of connection attempts.
$threshold_crossed: A function that generates a notice when the threshold is crossed, indicating potential port scanning activity.
Conclusion
This Zeek script provides a mechanism for detecting port scanning activity within a network by monitoring connection attempts and generating notices when suspicious activity is observed.