### Before/After Field Mapping Example

**Field Name Mapping:**

| Zeek/Normalized Field | ECS Field |
|----------------------|-----------|
| `src_ip` | `source.ip` |
| `dst_ip` | `destination.ip` |
| `src_port` | `source.port` |
| `dst_port` | `destination.port` |
| `protocol` | `network.transport` |
| `timestamp` | `@timestamp` |
| `uid` | `event.id` |
| `service` | `network.protocol` |
| `duration_sec` | `event.duration` |
| `bytes_sent` | `source.bytes` |
| `bytes_recv` | `destination.bytes` |
| `packets_sent` | `source.packets` |
| `packets_recv` | `destination.packets` |
| `conn_state` | `zeek.connection.state` |
| `log_type` | `event.dataset` |
| `dns_query` | `dns.question.name` |
| `dns_qtype` | `dns.question.type` |
| `dns_rcode` | `dns.response_code` |
| `dns_answers` | `dns.answers.name` |
| `ti_match` | `threat.indicator.matched` |

**Sample Data Transformation:**

*Before (Normalized Schema):*
```
                       timestamp log_type                 uid         src_ip  src_port         dst_ip  dst_port protocol service  duration_sec  bytes_sent  bytes_recv  packets_sent  packets_recv conn_state        dns_query dns_qtype dns_rcode      dns_answers  ti_match
0 2025-11-03 08:12:34.112000+...     conn  CYfOwn3KhUWXr2GnVe  192.168.1.100     52134  93.184.216.34       443      tcp     ssl         1.232        3420       14820            12            15         SF             <NA>      <NA>      <NA>             <NA>     False
1 2025-11-03 08:12:34.450000+...      dns  CbNCRo1MkFJPBcb3ai  192.168.1.100     52135        8.8.8.8        53      udp    <NA>          <NA>        <NA>        <NA>          <NA>          <NA>       <NA>  www.example.com         A   NOERROR  [93.184.216.34]     False
2 2025-11-03 08:12:34.500000+...     conn  CbNCRo1MkFJPBcb3ai  192.168.1.100     52135        8.8.8.8        53      udp     dns         0.042          38          92             1             1         SF             <NA>      <NA>      <NA>             <NA>     False
```

*After (ECS Schema):*
```
                    @timestamp event.kind event.category event.dataset            event.id  event.duration      source.ip  source.port  source.bytes  source.packets destination.ip  destination.port  destination.bytes  destination.packets network.transport network.protocol dns.question.name dns.question.type dns.response_code  threat.indicator.matched zeek.connection.state dns.answers.name
0  2025-11-03T08:12:34.112000Z      event        network          conn  CYfOwn3KhUWXr2GnVe           1.232  192.168.1.100        52134          3420              12  93.184.216.34               443              14820                   15               tcp              ssl              <NA>              <NA>              <NA>                     False                    SF             <NA>
1  2025-11-03T08:12:34.450000Z      event        network           dns  CbNCRo1MkFJPBcb3ai            <NA>  192.168.1.100        52135          <NA>            <NA>        8.8.8.8                53               <NA>                 <NA>               udp             <NA>   www.example.com                 A           NOERROR                     False                  <NA>  [93.184.216.34]
2  2025-11-03T08:12:34.500000Z      event        network          conn  CbNCRo1MkFJPBcb3ai           0.042  192.168.1.100        52135            38               1        8.8.8.8                53                 92                    1               udp              dns              <NA>              <NA>              <NA>                     False                    SF             <NA>
```