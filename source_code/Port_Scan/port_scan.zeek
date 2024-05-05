@load base/frameworks/sumstats
@load base/frameworks/notice

module Scancheck;

export {
    redef enum Notice::Type += {
        Port_Scan_Detect,
    };

    const threshold=10.0 &redef;



    }

event connection_attempt(c: connection)
{
    SumStats::observe("conn attempted",
    SumStats::Key($host=c$id$orig_h,$str=cat(c$id$resp_h)),
    SumStats::Observation($num=1));
}
event zeek_init() &priority=5 {
    local r1 =SumStats::Reducer($stream="conn attempted",$apply=set(SumStats::SUM));
    SumStats::create([
                    $name="finding port scanners",
                    $epoch = 5min,
                    $reducers= set(r1),
                    $threshold=threshold,
                    $threshold_val(key: SumStats::Key, result: SumStats::Result) =
                    {
                        return result["conn attempted"]$sum;
                    },
                    $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
                    {
                        local msg= fmt("%s attempted %.0f or more connections", key$host, result["conn attempted"]$sum);
                        NOTICE([$note=Port_Scan_Detect,
                            $msg=msg,
                            $src=key$host,
                            $dst=to_addr(key$str),
                            $identifier=cat(key$host)
                            ]);
                    }
    ]);
}
~                                                                                                                                                                                                          
~                