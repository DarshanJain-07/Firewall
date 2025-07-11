#!/bin/bash

FIREWALL_SCRIPT="firewall.py"
MONITOR_SCRIPT="monitor_firewall.py"

case "$1" in
    start)
        echo "Starting firewall..."
        python3 "$FIREWALL_SCRIPT" &
        echo "Firewall started"
        ;;
    stop)
        echo "Stopping firewall..."
        pkill -f "$FIREWALL_SCRIPT"
        pkill -f "$MONITOR_SCRIPT"
        echo "Firewall stopped"
        ;;
    restart)
        echo "Restarting firewall..."
        pkill -f "$FIREWALL_SCRIPT"
        sleep 2
        python3 "$FIREWALL_SCRIPT" &
        echo "Firewall restarted"
        ;;
    monitor)
        echo "Starting firewall with monitoring..."
        python3 "$MONITOR_SCRIPT"
        ;;
    status)
        if pgrep -f "$FIREWALL_SCRIPT" > /dev/null; then
            echo "✅ Firewall is running"
        else
            echo "❌ Firewall is not running"
        fi
        
        if pgrep -f "$MONITOR_SCRIPT" > /dev/null; then
            echo "✅ Monitor is running"
        else
            echo "❌ Monitor is not running"
        fi
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|monitor|status}"
        echo ""
        echo "Commands:"
        echo "  start   - Start firewall only"
        echo "  stop    - Stop firewall and monitor"
        echo "  restart - Restart firewall"
        echo "  monitor - Start firewall with monitoring"
        echo "  status  - Check if firewall/monitor is running"
        exit 1
        ;;
esac
