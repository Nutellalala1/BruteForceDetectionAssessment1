import datetime
from collections import defaultdict
from typing import List, Dict, Tuple

# Sample login attempt data
sample_login_data = [
    {"username": "alice", "ip": "192.168.1.100", "timestamp": "2025-11-12 10:00:00", "status": "success"},
    {"username": "bob", "ip": "192.168.1.101", "timestamp": "2025-11-12 10:01:00", "status": "failed"},
    {"username": "bob", "ip": "192.168.1.101", "timestamp": "2025-11-12 10:01:30", "status": "failed"},
    {"username": "bob", "ip": "192.168.1.101", "timestamp": "2025-11-12 10:02:00", "status": "failed"},
    {"username": "bob", "ip": "192.168.1.101", "timestamp": "2025-11-12 10:02:30", "status": "failed"},
    {"username": "bob", "ip": "192.168.1.101", "timestamp": "2025-11-12 10:03:00", "status": "failed"},
    {"username": "charlie", "ip": "192.168.1.102", "timestamp": "2025-11-12 10:05:00", "status": "success"},
    {"username": "admin", "ip": "10.0.0.50", "timestamp": "2025-11-12 10:10:00", "status": "failed"},
    {"username": "admin", "ip": "10.0.0.50", "timestamp": "2025-11-12 10:10:15", "status": "failed"},
    {"username": "admin", "ip": "10.0.0.50", "timestamp": "2025-11-12 10:10:30", "status": "failed"},
    {"username": "root", "ip": "10.0.0.50", "timestamp": "2025-11-12 10:10:45", "status": "failed"},
    {"username": "administrator", "ip": "10.0.0.50", "timestamp": "2025-11-12 10:11:00", "status": "failed"},
    {"username": "alice", "ip": "192.168.1.100", "timestamp": "2025-11-12 10:15:00", "status": "success"},
]


# ALGORITHM 1: Sliding Time Window Detector

class SlidingWindowDetector:
    """
    Detects brute force attacks using a sliding time window approach.
    
    Rules:
    1. Track failed login attempts per username within a time window
    2. Track failed login attempts per IP address within a time window
    3. Flag as brute force if threshold is exceeded
    4. Uses real-time sliding window (only considers recent attempts)
    """
    
    def __init__(self, time_window_minutes=5, username_threshold=3, ip_threshold=5):
        self.time_window = datetime.timedelta(minutes=time_window_minutes)
        self.username_threshold = username_threshold
        self.ip_threshold = ip_threshold
        
    def detect(self, login_attempts: List[Dict]) -> Dict:
        """Analyze login attempts and detect brute force patterns."""
        
        # Sort attempts by timestamp
        sorted_attempts = sorted(
            login_attempts, 
            key=lambda x: datetime.datetime.strptime(x['timestamp'], '%Y-%m-%d %H:%M:%S')
        )
        
        results = {
            'flagged_users': set(),
            'flagged_ips': set(),
            'detailed_alerts': []
        }
        
        # Track failed attempts
        username_failures = defaultdict(list)
        ip_failures = defaultdict(list)
        
        for attempt in sorted_attempts:
            timestamp = datetime.datetime.strptime(attempt['timestamp'], '%Y-%m-%d %H:%M:%S')
            username = attempt['username']
            ip = attempt['ip']
            status = attempt['status']
            
            if status == 'failed':
                # Add to tracking
                username_failures[username].append(timestamp)
                ip_failures[ip].append(timestamp)
                
                # Clean old entries outside time window
                username_failures[username] = [
                    t for t in username_failures[username] 
                    if timestamp - t <= self.time_window
                ]
                ip_failures[ip] = [
                    t for t in ip_failures[ip] 
                    if timestamp - t <= self.time_window
                ]
                
                # Check thresholds
                if len(username_failures[username]) >= self.username_threshold:
                    results['flagged_users'].add(username)
                    results['detailed_alerts'].append({
                        'type': 'username_brute_force',
                        'username': username,
                        'failed_attempts': len(username_failures[username]),
                        'timestamp': attempt['timestamp'],
                        'severity': 'HIGH'
                    })
                
                if len(ip_failures[ip]) >= self.ip_threshold:
                    results['flagged_ips'].add(ip)
                    results['detailed_alerts'].append({
                        'type': 'ip_brute_force',
                        'ip': ip,
                        'failed_attempts': len(ip_failures[ip]),
                        'timestamp': attempt['timestamp'],
                        'severity': 'CRITICAL'
                    })
        
        return results

# ALGORITHM 2: Pattern-Based Progressive Penalty Detector

class ProgressivePenaltyDetector:
    """
    Detects brute force attacks using progressive penalty scoring.
    
    Rules:
    1. Assign penalty points for each failed attempt
    2. Increase penalty multiplier for rapid successive failures
    3. Add bonus penalties for targeting common usernames (admin, root, etc.)
    4. Decay penalty over time for legitimate users
    5. Flag when total penalty score exceeds threshold
    """
    
    def __init__(self, base_penalty=10, threshold=50):
        self.base_penalty = base_penalty
        self.threshold = threshold
        self.common_targets = {'admin', 'root', 'administrator', 'user', 'test'}
        
    def detect(self, login_attempts: List[Dict]) -> Dict:
        """Analyze login attempts using progressive penalty scoring."""
        
        sorted_attempts = sorted(
            login_attempts,
            key=lambda x: datetime.datetime.strptime(x['timestamp'], '%Y-%m-%d %H:%M:%S')
        )
        
        # Track scores and patterns
        username_scores = defaultdict(lambda: {'score': 0, 'last_failure_time': None, 'consecutive_failures': 0})
        ip_scores = defaultdict(lambda: {'score': 0, 'last_failure_time': None, 'consecutive_failures': 0})
        
        results = {
            'flagged_users': {},
            'flagged_ips': {},
            'detailed_alerts': []
        }
        
        for attempt in sorted_attempts:
            timestamp = datetime.datetime.strptime(attempt['timestamp'], '%Y-%m-%d %H:%M:%S')
            username = attempt['username']
            ip = attempt['ip']
            status = attempt['status']
            
            if status == 'failed':
                # Calculate username penalty
                username_penalty = self._calculate_penalty(
                    username_scores[username], 
                    timestamp, 
                    username in self.common_targets
                )
                username_scores[username]['score'] += username_penalty
                username_scores[username]['last_failure_time'] = timestamp
                username_scores[username]['consecutive_failures'] += 1
                
                # Calculate IP penalty
                ip_penalty = self._calculate_penalty(
                    ip_scores[ip], 
                    timestamp, 
                    False
                )
                ip_scores[ip]['score'] += ip_penalty
                ip_scores[ip]['last_failure_time'] = timestamp
                ip_scores[ip]['consecutive_failures'] += 1
                
                # Check thresholds
                if username_scores[username]['score'] >= self.threshold:
                    results['flagged_users'][username] = username_scores[username]['score']
                    results['detailed_alerts'].append({
                        'type': 'username_high_penalty',
                        'username': username,
                        'score': username_scores[username]['score'],
                        'consecutive_failures': username_scores[username]['consecutive_failures'],
                        'timestamp': attempt['timestamp'],
                        'severity': 'HIGH'
                    })
                
                if ip_scores[ip]['score'] >= self.threshold:
                    results['flagged_ips'][ip] = ip_scores[ip]['score']
                    results['detailed_alerts'].append({
                        'type': 'ip_high_penalty',
                        'ip': ip,
                        'score': ip_scores[ip]['score'],
                        'consecutive_failures': ip_scores[ip]['consecutive_failures'],
                        'timestamp': attempt['timestamp'],
                        'severity': 'CRITICAL'
                    })
            else:
                # Success resets consecutive failures but keeps some score
                username_scores[username]['consecutive_failures'] = 0
                username_scores[username]['score'] = max(0, username_scores[username]['score'] - 5)
                ip_scores[ip]['consecutive_failures'] = 0
                ip_scores[ip]['score'] = max(0, ip_scores[ip]['score'] - 5)
        
        return results
    
    def _calculate_penalty(self, entity_data: Dict, current_time: datetime.datetime, is_common_target: bool) -> int:
        """Calculate penalty based on patterns."""
        penalty = self.base_penalty
        
        # Rapid succession multiplier (attempts within 30 seconds)
        if entity_data['last_failure_time']:
            time_diff = (current_time - entity_data['last_failure_time']).total_seconds()
            if time_diff < 30:
                penalty *= (1 + entity_data['consecutive_failures'] * 0.5)
        
        # Common target bonus penalty
        if is_common_target:
            penalty *= 1.5
        
        return int(penalty)



# DEMONSTRATION

def demonstrate_algorithms():
    """Run both algorithms and display results."""
    
    print("=" * 80)
    print("BRUTE FORCE LOGIN DETECTION - ALGORITHM COMPARISON")
    print("=" * 80)
    print(f"\nAnalyzing {len(sample_login_data)} login attempts...\n")
    
    # Algorithm 1: Sliding Window
    print("-" * 80)
    print("ALGORITHM 1: Sliding Time Window Detector")
    print("-" * 80)
    print("Rules: Detects patterns within a 5-minute sliding window")
    print("Thresholds: 3 failures/username, 5 failures/IP\n")
    
    detector1 = SlidingWindowDetector(time_window_minutes=5, username_threshold=3, ip_threshold=5)
    results1 = detector1.detect(sample_login_data)
    
    print(f"Flagged Usernames: {results1['flagged_users']}")
    print(f"Flagged IP Addresses: {results1['flagged_ips']}")
    print(f"\nDetailed Alerts ({len(results1['detailed_alerts'])}):")
    for alert in results1['detailed_alerts']:
        print(f"  - [{alert['severity']}] {alert['type']}: ", end="")
        if 'username' in alert:
            print(f"User '{alert['username']}' - {alert['failed_attempts']} failures at {alert['timestamp']}")
        else:
            print(f"IP '{alert['ip']}' - {alert['failed_attempts']} failures at {alert['timestamp']}")
    
    # Algorithm 2: Progressive Penalty
    print("\n" + "-" * 80)
    print("ALGORITHM 2: Pattern-Based Progressive Penalty Detector")
    print("-" * 80)
    print("Rules: Assigns penalty scores based on patterns, rapid attempts, and target types")
    print("Threshold: 50 penalty points\n")
    
    detector2 = ProgressivePenaltyDetector(base_penalty=10, threshold=50)
    results2 = detector2.detect(sample_login_data)
    
    print(f"Flagged Usernames: {dict(results2['flagged_users'])}")
    print(f"Flagged IP Addresses: {dict(results2['flagged_ips'])}")
    print(f"\nDetailed Alerts ({len(results2['detailed_alerts'])}):")
    for alert in results2['detailed_alerts']:
        print(f"  - [{alert['severity']}] {alert['type']}: ", end="")
        if 'username' in alert:
            print(f"User '{alert['username']}' - Score: {alert['score']}, Consecutive: {alert['consecutive_failures']}")
        else:
            print(f"IP '{alert['ip']}' - Score: {alert['score']}, Consecutive: {alert['consecutive_failures']}")
    
    # Summary comparison
    print("\n" + "=" * 80)
    print("COMPARISON SUMMARY")
    print("=" * 80)
    print(f"Algorithm 1 detected {len(results1['flagged_users'])} suspicious users and {len(results1['flagged_ips'])} suspicious IPs")
    print(f"Algorithm 2 detected {len(results2['flagged_users'])} suspicious users and {len(results2['flagged_ips'])} suspicious IPs")
    print("\nKey Differences:")
    print("- Algorithm 1: Simple threshold-based, good for immediate threats")
    print("- Algorithm 2: Sophisticated scoring, adapts to attack patterns and intensity")


if __name__ == "__main__":
    demonstrate_algorithms()