##! Config File for Zeek HTTP RCE script

## Determines whether to check just inbound traffic or also include outbound traffic.
## Set this to True if you only want to check traffic destined to your define local networks regardless of origin.
## Set this to false if you want to check traffic destined to any network regardless of origin.
## Recommend setting this to "T" to consume fewer resources for Zeek clusters, but "F" if running on a pcap file. 
const check_only_local_net: bool = F;


## In one's observation, RCE attempts can happen sporadically over a long period of time.
## The RCE_request_threshold is intentionally set low, with the interval set high
## to catch the "low and slow" types of scanners. These are somewhat intuitively arbitrary
## but not scientific.

## Defines the threshold that determines if an RCE attack
## is ongoing based on the number of requests that appear to be
## RCE attacks.
const rce_requests_threshold: double = 3.0 &redef;


## Interval at which to watch for the
## :zeek:id:`HTTP::rce_requests_threshold` variable to be crossed.
## At the end of each interval the counter is reset.
const rce_requests_interval = 120min &redef;


## Collecting samples will add extra data to the notice.
## Disable sample collection by setting this value to 0.
const collect_RCE_samples = 3 &redef;


