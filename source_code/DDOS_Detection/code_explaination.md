# Zeek Script Explanation

## Overview

The provided Zeek script is designed to detect SYN flood attacks within a network. It employs event handlers to monitor network traffic, sample connection attempts, and generate notices when SYN flood activity is detected.

## Script Breakdown

### 1. Loading Frameworks

The script starts by loading necessary frameworks for Zeek, such as notice.

```zeek
@load notice
```

### 2. Enumeration Definition
An enumeration named Notice is defined to categorize different types of notices related to SYN flood attacks.\

```
redef enum Notice += {
    SynFloodStart,    # start of syn-flood against a certain victim
    SynFloodEnd,      # end of syn-flood against a certain victim
    SynFloodStatus,   # report of ongoing syn-flood
};
```
### 3. Global Variables
Several global variables are defined to set thresholds, intervals, and sampling rates for SYN flood detection. Tables are also initialized to store connection attempts and victim information.\
```
global SYNFLOOD_THRESHOLD = 15000 &redef;
global SYNFLOOD_INTERVAL = 60 secs &redef;
global SYNFLOOD_REPORT_INTERVAL = 1 mins &redef;

# Sample connections by one out of x.
global SYNFLOOD_SAMPLE_RATE = 100 &redef;

global SYNFLOOD_VICTIM_SAMPLE_RATE = 0.01 &redef;

global conn_attempts: table[addr] of count &default = 0;
global victim_attempts: table[addr,addr] of count
	&default = 0  &read_expire = 5mins;

global max_sources = 100;
global current_victims: table[addr] of set[addr] &read_expire = 60mins;
global accumulated_conn_attempts: table[addr] of count &default = 0;

global sample_count = 0;
global interval_start: time = 0;

```

### 4. Event Handlers
new_connection: This event handler is triggered for each new network connection. It samples connections and triggers a notice if SYN flood activity is detected.
```
event new_connection(c: connection)
	{
	if ( c$id$resp_h in current_victims )
		{
		++conn_attempts[c$id$resp_h];

		local srcs = current_victims[c$id$resp_h];
		if ( length(srcs) < max_sources )
			add srcs[c$id$orig_h];
		return;
		}

	if ( ++sample_count % SYNFLOOD_SAMPLE_RATE == 0 )
		{
		local ip = c$id$resp_h;

		if ( ++conn_attempts[ip] * SYNFLOOD_SAMPLE_RATE >
		     SYNFLOOD_THRESHOLD )
			{
			NOTICE([$note=SynFloodStart, $src=ip,
				   $msg=fmt("Start of syn-flood against %s; sampling packets now", ip)]);

			add current_victims[ip][c$id$orig_h];

			# Drop most packets to victim.
			#install_dst_addr_filter(ip, 0,
			#		1 - SYNFLOOD_VICTIM_SAMPLE_RATE);
			# Drop all packets from victim.
			#install_src_addr_filter(ip, 0, 1.0);
			}
		}
	}

```

check_synflood: Scheduled to run at regular intervals, it checks for ongoing SYN flood attacks and stops sampling if the attack has ended.
```
event check_synflood()
	{
	for ( ip in current_victims )
		{
		accumulated_conn_attempts[ip] =
			accumulated_conn_attempts[ip] + conn_attempts[ip];

		if ( conn_attempts[ip] * (1 / SYNFLOOD_VICTIM_SAMPLE_RATE) <
		     SYNFLOOD_THRESHOLD )
			{
			NOTICE([$note=SynFloodEnd, $src=ip, $n=length(current_victims[ip]),
				   $msg=fmt("end of syn-flood against %s; stopping sampling",
					ip)]);
 
			delete current_victims[ip];
			#uninstall_dst_addr_filter(ip);
			#uninstall_src_addr_filter(ip);
			}
		}

	clear_table(conn_attempts);
	schedule SYNFLOOD_INTERVAL { check_synflood() };
	}

```
report_synflood: Scheduled to run at regular intervals, it reports the status of ongoing SYN flood attacks, including estimated connection counts.

```
event report_synflood()
	{
	for ( ip in current_victims )
		{
		local est_num_conn = accumulated_conn_attempts[ip] *
					(1 / SYNFLOOD_VICTIM_SAMPLE_RATE);

		local interv: interval;

		if ( interval_start != 0 )
			interv = network_time() - interval_start;
		else
			interv = SYNFLOOD_INTERVAL;

		NOTICE([$note=SynFloodStatus, $src=ip, $n=length(current_victims[ip]),
			   $msg=fmt("syn-flood against %s; estimated %.0f connections in last %s",
				    ip, est_num_conn, interv)]);
		}

	clear_table(accumulated_conn_attempts);

	schedule SYNFLOOD_REPORT_INTERVAL { report_synflood() };
	interval_start = network_time();
	}

```
### 5. Initialization Event
The zeek_init event handler is triggered during Zeek initialization. This event handler initializes the script, scheduling the check_synflood and report_synflood events.

```
event zeek_init()
	{
	schedule SYNFLOOD_INTERVAL { check_synflood() };
	schedule SYNFLOOD_REPORT_INTERVAL { report_synflood() };
	}
```
### 6. Conclusion
This Zeek script provides a comprehensive framework for detecting and monitoring SYN flood attacks within a network. It leverages event-driven analysis and periodic reporting to provide insights into ongoing attacks.