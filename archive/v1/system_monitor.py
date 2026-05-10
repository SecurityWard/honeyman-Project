#!/usr/bin/env python3
"""
Honeypot System Health Monitor
Monitors all honeypot services and provides health status
"""

import subprocess
import json
import psutil
import time
from datetime import datetime
from pathlib import Path
import requests
from elasticsearch import Elasticsearch

class HoneypotMonitor:
    def __init__(self):
        self.es = Elasticsearch(['http://localhost:9200'])
        self.services = [
            'honeypot-usb-advanced',
            'honeypot-wifi-detector',
            'honeypot-ble-enhanced',
            'honeypot-airdrop',
            'honeypot-multi-vector',
            'honeypot-forwarder',
            'honeypot-canary-forwarder'
        ]
        self.docker_containers = [
            'honeypot-elasticsearch',
            'honeypot-kibana',
            'honeypot-web',
            'honeypot-opencanary'
        ]
        self.vps_dashboard = 'http://72.60.25.24:8080/api/threats/stats'
        
    def check_service_status(self, service_name):
        """Check if a systemd service is running"""
        try:
            result = subprocess.run(
                ['systemctl', 'is-active', f'{service_name}.service'],
                capture_output=True, text=True
            )
            return result.stdout.strip() == 'active'
        except Exception as e:
            return False
            
    def check_docker_container(self, container_name):
        """Check if a Docker container is running"""
        try:
            result = subprocess.run(
                ['docker', 'inspect', '-f', '{{.State.Running}}', container_name],
                capture_output=True, text=True
            )
            return result.stdout.strip() == 'true'
        except Exception:
            return False
            
    def check_elasticsearch(self):
        """Check Elasticsearch health"""
        try:
            health = self.es.cluster.health()
            return health['status'] in ['green', 'yellow']
        except Exception:
            return False
            
    def check_vps_dashboard(self):
        """Check VPS dashboard connectivity"""
        try:
            response = requests.get(self.vps_dashboard, timeout=5)
            return response.status_code == 200
        except Exception:
            return False
            
    def get_system_resources(self):
        """Get system resource usage"""
        return {
            'cpu_percent': psutil.cpu_percent(interval=1),
            'memory_percent': psutil.virtual_memory().percent,
            'disk_percent': psutil.disk_usage('/').percent,
            'network_connections': len(psutil.net_connections())
        }
        
    def get_threat_statistics(self):
        """Get threat statistics from Elasticsearch"""
        try:
            # Last 24 hours
            result = self.es.search(
                index='honeypot-*',
                body={
                    'size': 0,
                    'query': {
                        'range': {
                            'timestamp': {
                                'gte': 'now-24h'
                            }
                        }
                    },
                    'aggs': {
                        'by_source': {
                            'terms': {
                                'field': 'source.keyword',
                                'size': 10
                            }
                        },
                        'threat_count': {
                            'value_count': {
                                'field': 'threat_score'
                            }
                        }
                    }
                }
            )
            return {
                'total_24h': result['hits']['total']['value'],
                'sources': result['aggregations']['by_source']['buckets']
            }
        except Exception:
            return {'total_24h': 0, 'sources': []}
            
    def generate_health_report(self):
        """Generate comprehensive health report"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'services': {},
            'docker': {},
            'elasticsearch': False,
            'vps_dashboard': False,
            'system_resources': {},
            'threat_stats': {},
            'overall_health': 'HEALTHY'
        }
        
        # Check services
        for service in self.services:
            report['services'][service] = self.check_service_status(service)
            
        # Check Docker containers
        for container in self.docker_containers:
            report['docker'][container] = self.check_docker_container(container)
            
        # Check Elasticsearch
        report['elasticsearch'] = self.check_elasticsearch()
        
        # Check VPS Dashboard
        report['vps_dashboard'] = self.check_vps_dashboard()
        
        # Get system resources
        report['system_resources'] = self.get_system_resources()
        
        # Get threat statistics
        report['threat_stats'] = self.get_threat_statistics()
        
        # Determine overall health
        service_health = all(report['services'].values())
        docker_health = all(report['docker'].values())
        
        if not service_health or not docker_health:
            report['overall_health'] = 'CRITICAL'
        elif not report['elasticsearch'] or not report['vps_dashboard']:
            report['overall_health'] = 'WARNING'
        elif report['system_resources']['cpu_percent'] > 80 or \
             report['system_resources']['memory_percent'] > 90:
            report['overall_health'] = 'WARNING'
            
        return report
        
    def print_status(self, report):
        """Print formatted status report"""
        print("\n" + "="*60)
        print(f"🏥 HONEYPOT SYSTEM HEALTH CHECK - {report['timestamp']}")
        print("="*60)
        
        # Overall Status
        health_icon = "✅" if report['overall_health'] == 'HEALTHY' else \
                      "⚠️" if report['overall_health'] == 'WARNING' else "❌"
        print(f"\n{health_icon} Overall Health: {report['overall_health']}")
        
        # Services
        print("\n📊 Systemd Services:")
        for service, status in report['services'].items():
            icon = "✅" if status else "❌"
            print(f"  {icon} {service}: {'Running' if status else 'Stopped'}")
            
        # Docker
        print("\n🐋 Docker Containers:")
        for container, status in report['docker'].items():
            icon = "✅" if status else "❌"
            print(f"  {icon} {container}: {'Running' if status else 'Stopped'}")
            
        # Infrastructure
        print("\n🔗 Infrastructure:")
        print(f"  {'✅' if report['elasticsearch'] else '❌'} Elasticsearch: {'Healthy' if report['elasticsearch'] else 'Down'}")
        print(f"  {'✅' if report['vps_dashboard'] else '❌'} VPS Dashboard: {'Connected' if report['vps_dashboard'] else 'Unreachable'}")
        
        # Resources
        print("\n💻 System Resources:")
        res = report['system_resources']
        print(f"  CPU Usage: {res['cpu_percent']:.1f}%")
        print(f"  Memory Usage: {res['memory_percent']:.1f}%")
        print(f"  Disk Usage: {res['disk_percent']:.1f}%")
        print(f"  Network Connections: {res['network_connections']}")
        
        # Threats
        print("\n🚨 Threat Statistics (Last 24h):")
        print(f"  Total Events: {report['threat_stats']['total_24h']}")
        if report['threat_stats']['sources']:
            print("  Top Sources:")
            for source in report['threat_stats']['sources'][:3]:
                print(f"    - {source['key']}: {source['doc_count']} events")
                
        print("\n" + "="*60)
        
    def save_report(self, report):
        """Save report to file"""
        report_dir = Path('/home/burner/honeypot-minimal/logs/health_reports')
        report_dir.mkdir(exist_ok=True)
        
        filename = report_dir / f"health_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
            
        # Also save to Elasticsearch
        try:
            self.es.index(
                index='honeypot-health',
                body=report
            )
        except Exception:
            pass
            
def main():
    monitor = HoneypotMonitor()
    
    while True:
        try:
            report = monitor.generate_health_report()
            monitor.print_status(report)
            monitor.save_report(report)
            
            # Alert on critical issues
            if report['overall_health'] == 'CRITICAL':
                print("\n⚠️  CRITICAL: System requires immediate attention!")
                
            # Wait 5 minutes before next check
            time.sleep(300)
            
        except KeyboardInterrupt:
            print("\n👋 Health monitor stopped")
            break
        except Exception as e:
            print(f"\n❌ Error during health check: {e}")
            time.sleep(60)

if __name__ == '__main__':
    main()