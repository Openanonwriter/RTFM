function Show-MainMenu {
    while ($true) {
        Clear-Host
        Write-Host "=== Network Diagnostic Tool Menu ==="
        Write-Host "(iperf3) Bandwith Test"
        Write-Host "(nmap) Check ports and hosts on network"
        Write-Host "(TNC)Test-NetConnection"
        Write-Host "(Ping)"
        Write-Host "(Tracert) Trace Route"

        $choice = Read-Host "Enter your choice"

        switch ($choice) {
            'iperf3' { iperf3-subMenu }
            '2' { Write-Host "You chose Option 2" }
            '3' { Show-SubMenu }
            'q' { exit }
            default { Write-Host "Invalid choice. Press ENTER and Please try again."  -ForegroundColor Red
            Read-Host }
        }
    }
}

function iperf3-submenu {
    while ($true) {
        $iperfPath = Get-ChildItem -Path .\ -Filter iperf3.exe -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName
        if ($null -ne $iperfPath) {
        
        Clear-Host
        Write-Host "=== iperf3 ==="
        Write-Host "(C)lient Mode IPV4"
        Write-Host "(S)erver Mode IPV4"
        Write-Host "Custom (Args)"
        Write-Host "(Q) Back to Main Menu"
    } else {
        Write-Host "iperf3.exe not found in any subdirectory of the Tools directory." -ForegroundColor Red
        Read-Host
        Show-MainMenu
    }
        $subChoice = Read-Host "Enter your subchoice"

        switch ($subChoice) {
            'c' { 
                Clear-Host
                Write-host "This will run with -c applied"
                $iperfIP = Read-Host "Enter IPV4 Address"
                $iperfport = Read-Host "Enter A Port Number"
                $iperfArgs = Read-Host "Enter Aditional Argments if you want"
                Start-Process -FilePath $iperfPath -ArgumentList "-c $iperfIP -p $iperfport $iperfArgs"
                Read-Host
             }
            's' { 
                Clear-Host
                Write-host "This will run with -s applied"
                $iperfport = Read-Host "Enter A Port Number"
                $iperfArgs = Read-Host "Enter Aditional Argments if you want"
                Start-Process -FilePath $iperfPath -ArgumentList "-s -p $iperfport $iperfArgs"
                Read-Host
            }
        'args' {                 
            Clear-Host
$x = @"
Usage: iperf [-s|-c host] [options]
       iperf [-h|--help] [-v|--version]

Server or Client:
  -p, --port      #         server port to listen on/connect to
  -f, --format    [kmgKMG]  format to report: Kbits, Mbits, KBytes, MBytes
  -i, --interval  #         seconds between periodic bandwidth reports
  -F, --file name           xmit/recv the specified file
  -B, --bind      <host>    bind to a specific interface
  -V, --verbose             more detailed output
  -J, --json                output in JSON format
  --logfile f               send output to a log file
  -d, --debug               emit debugging output
  -v, --version             show version information and quit
  -h, --help                show this message and quit
Server specific:
  -s, --server              run in server mode
  -D, --daemon              run the server as a daemon
  -I, --pidfile file        write PID file
  -1, --one-off             handle one client connection then exit
Client specific:
  -c, --client    <host>    run in client mode, connecting to <host>
  -u, --udp                 use UDP rather than TCP
  -b, --bandwidth #[KMG][/#] target bandwidth in bits/sec (0 for unlimited)
                            (default 1 Mbit/sec for UDP, unlimited for TCP)
                            (optional slash and packet count for burst mode)
  -t, --time      #         time in seconds to transmit for (default 10 secs)
  -n, --bytes     #[KMG]    number of bytes to transmit (instead of -t)
  -k, --blockcount #[KMG]   number of blocks (packets) to transmit (instead of -t or -n)
  -l, --len       #[KMG]    length of buffer to read or write
                            (default 128 KB for TCP, 8 KB for UDP)
  --cport         <port>    bind to a specific client port (TCP and UDP, default: ephemeral port)
  -P, --parallel  #         number of parallel client streams to run
  -R, --reverse             run in reverse mode (server sends, client receives)
  -w, --window    #[KMG]    set window size / socket buffer size
  -M, --set-mss   #         set TCP/SCTP maximum segment size (MTU - 40 bytes)
  -N, --no-delay            set TCP/SCTP no delay, disabling Nagle's Algorithm
  -4, --version4            only use IPv4
  -6, --version6            only use IPv6
  -S, --tos N               set the IP 'type of service'
  -Z, --zerocopy            use a 'zero copy' method of sending data
  -O, --omit N              omit the first n seconds
  -T, --title str           prefix every output line with this string
  --get-server-output       get results from server
  --udp-counters-64bit      use 64-bit counters in UDP test packets

[KMG] indicates options that support a K/M/G suffix for kilo-, mega-, or giga-
"@
Write-Host $x
            $iperfArgs = Read-Host "Enter Args"
            Start-Process $iperfPath -ArgumentList "$iperfArgs"
            Read-Host 
        }
        'q' { Show-MainMenu }
        default { Write-Host "Invalid selection. Please choose again." 
                Read-Host}
        } 
    }
}

function nmap-submenu {
    while ($true) {
        Clear-Host
        Write-Host "=== Submenu ==="
        Write-Host "A. Suboption A"
        Write-Host "B. Suboption B"
        Write-Host "Q. Back to Main Menu"

        $subChoice = Read-Host "Enter your subchoice"

        switch ($subChoice) {
            'a' { Write-Host "You chose Suboption A" }
            'b' { Write-Host "You chose Suboption B" }
            'q' { break }
            default { Write-Host "Invalid subchoice. Please try again." }
        }
    }
}

Show-MainMenu