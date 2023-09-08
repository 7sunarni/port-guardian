# port-guard
go http-server config iptables port whitelist

## usage:
1. prepare your guard.json
```json
{
    "httpPort":"54321",
    "ports":[
        {"port":"56780","passports":[{"path":"55h","name":"55h"}]}
    ]
}
```
2. just run `go run main.go`
3. now your server listen on `0.0.0.0:54321`, and will deny all tcp traffic to `0.0.0.0:56789`
4. just visit `$server_ip:54321/56789/55h`, then guard will put your client ip which you visited from in white list for tcp traffic to `0.0.0.0:56789`
5. if some bad guy try to visit some http routes not existed for sniffing, e.g. $server_ip:54321/i-am-bad-man, after 5 times try, guard will deny client ip to visit 54321
