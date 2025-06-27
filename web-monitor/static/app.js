// Advanced monitoring features for NoSleep-Ops Web Interface

class AttackMonitor {
    constructor() {
        this.attackHistory = [];
        this.defenseHistory = [];
        this.geoData = new Map();
        this.alertThresholds = {
            attacksPerMinute: 10,
            uniqueIPsPerHour: 50,
            criticalSeverityCount: 5
        };
        this.sounds = {
            newAttack: new Audio('data:audio/wav;base64,UklGRnoGAABXQVZFZm10IBAAAAABAAEAQB8AAEAfAAABAAgAZGF0YQoGAACBhYqFbF1fdJivrJBhNjVgodDbq2EcBj+a2/LDciUFLIHO8tiJNwgZaLvt559NEAxQp+PwtmMcBjiR1/LMeSwFJHfH8N2QQAoUXrTp66hVFApGn+DyvmQdBSuGzvPZiTkJE2m98OScTQwOUarm7blmHgU4k9n1unEoByJ2xe/eizELElyx5+2mUBELRZ3e8bllHgU'),
            defensiveAction: new Audio('data:audio/wav;base64,UklGRnoGAABXQVZFZm10IBAAAAABAAEAQB8AAEAfAAABAAgAZGF0YQoGAACBhYqFbF1fdJivrJBhNjVgodDbq2EcBj+a2/LDciUFLIHO8tiJNwgZaLvt559NEAxQp+PwtmMcBjiR1/LMeSwFJHfH8N2QQAoUXrTp66hVFApGn+DyvmQdBSuGzvPZiTkJE2m98OScTQwOUarm7blmHgU4k9n1unEoByJ2xe/eizELElyx5+2mUBELRZ3e8bllHgU')
        };
        this.init();
    }

    init() {
        this.setupGeolocation();
        this.setupAdvancedCharts();
        this.setupKeyboardShortcuts();
        this.setupNotifications();
    }

    setupGeolocation() {
        // Mock geolocation data for demonstration
        this.geoData.set('192.0.2.1', { country: 'US', city: 'New York', lat: 40.7128, lng: -74.0060 });
        this.geoData.set('192.0.2.100', { country: 'CN', city: 'Beijing', lat: 39.9042, lng: 116.4074 });
        this.geoData.set('192.0.2.200', { country: 'RU', city: 'Moscow', lat: 55.7558, lng: 37.6176 });
    }

    setupAdvancedCharts() {
        this.createHeatmapChart();
        this.createGeoChart();
        this.createThreatLevelChart();
    }

    createHeatmapChart() {
        const ctx = document.getElementById('heatmapChart');
        if (!ctx) return;

        this.heatmapChart = new Chart(ctx, {
            type: 'scatter',
            data: {
                datasets: [{
                    label: 'Attack Intensity',
                    data: [],
                    backgroundColor: function(context) {
                        const value = context.parsed.y;
                        const alpha = Math.min(value / 10, 1);
                        return `rgba(255, 0, 0, ${alpha})`;
                    }
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    x: {
                        type: 'time',
                        time: {
                            unit: 'minute'
                        },
                        title: {
                            display: true,
                            text: 'Time',
                            color: '#ffffff'
                        },
                        ticks: {
                            color: '#ffffff'
                        }
                    },
                    y: {
                        title: {
                            display: true,
                            text: 'Attack Count',
                            color: '#ffffff'
                        },
                        ticks: {
                            color: '#ffffff'
                        }
                    }
                },
                plugins: {
                    legend: {
                        labels: {
                            color: '#ffffff'
                        }
                    }
                }
            }
        });
    }

    createThreatLevelChart() {
        const ctx = document.getElementById('threatLevelChart');
        if (!ctx) return;

        this.threatLevelChart = new Chart(ctx, {
            type: 'radar',
            data: {
                labels: ['SSH Brute Force', 'Web Attacks', 'Port Scans', 'DDoS', 'Malware', 'Data Exfiltration'],
                datasets: [{
                    label: 'Current Threat Level',
                    data: [0, 0, 0, 0, 0, 0],
                    borderColor: '#ff6b6b',
                    backgroundColor: 'rgba(255, 107, 107, 0.2)',
                    pointBackgroundColor: '#ff6b6b'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    r: {
                        beginAtZero: true,
                        max: 10,
                        ticks: {
                            color: '#ffffff'
                        },
                        grid: {
                            color: 'rgba(255, 255, 255, 0.1)'
                        },
                        angleLines: {
                            color: 'rgba(255, 255, 255, 0.1)'
                        }
                    }
                },
                plugins: {
                    legend: {
                        labels: {
                            color: '#ffffff'
                        }
                    }
                }
            }
        });
    }

    setupKeyboardShortcuts() {
        document.addEventListener('keydown', (e) => {
            if (e.ctrlKey || e.metaKey) {
                switch(e.key) {
                    case 'b':
                        e.preventDefault();
                        this.quickBlock();
                        break;
                    case 'r':
                        e.preventDefault();
                        this.refreshData();
                        break;
                    case 'e':
                        e.preventDefault();
                        this.exportData();
                        break;
                    case 'f':
                        e.preventDefault();
                        this.toggleFullscreen();
                        break;
                }
            }
            
            // ESC key for emergency actions
            if (e.key === 'Escape') {
                this.emergencyMode();
            }
        });
    }

    setupNotifications() {
        if ('Notification' in window && Notification.permission === 'default') {
            Notification.requestPermission();
        }
    }

    processNewAttack(attack) {
        this.attackHistory.push(attack);
        this.checkAlertThresholds();
        this.updateThreatLevel(attack);
        this.playAttackSound();
        this.showNotification('New Attack Detected', `${attack.attack_type} from ${attack.source_ip}`);
        
        // Update advanced visualizations
        this.updateHeatmap();
        this.updateGeoData(attack);
    }

    processDefenseAction(defense) {
        this.defenseHistory.push(defense);
        this.playDefenseSound();
        this.showNotification('Defense Action', `${defense.action_type} executed`);
    }

    checkAlertThresholds() {
        const now = Date.now();
        const oneMinuteAgo = now - 60000;
        const oneHourAgo = now - 3600000;
        
        // Check attacks per minute
        const recentAttacks = this.attackHistory.filter(a => 
            new Date(a.timestamp).getTime() > oneMinuteAgo
        );
        
        if (recentAttacks.length > this.alertThresholds.attacksPerMinute) {
            this.triggerHighPriorityAlert('High attack frequency detected!');
        }
        
        // Check unique IPs per hour
        const hourlyAttacks = this.attackHistory.filter(a => 
            new Date(a.timestamp).getTime() > oneHourAgo
        );
        const uniqueIPs = new Set(hourlyAttacks.map(a => a.source_ip));
        
        if (uniqueIPs.size > this.alertThresholds.uniqueIPsPerHour) {
            this.triggerHighPriorityAlert('Distributed attack detected!');
        }
    }

    updateThreatLevel(attack) {
        if (!this.threatLevelChart) return;
        
        const threatMap = {
            'SSH_BRUTE_FORCE': 0,
            'SSH_USER_ENUM': 0,
            'SQL_INJECTION': 1,
            'XSS_ATTEMPT': 1,
            'DIRECTORY_TRAVERSAL': 1,
            'COMMAND_INJECTION': 1,
            'PORT_SCAN': 2,
            'DDOS_ATTEMPT': 3,
            'MALWARE_DETECTED': 4,
            'DATA_EXFILTRATION': 5
        };
        
        const index = threatMap[attack.attack_type];
        if (index !== undefined) {
            const currentData = this.threatLevelChart.data.datasets[0].data;
            currentData[index] = Math.min(currentData[index] + 1, 10);
            this.threatLevelChart.update();
        }
    }

    updateHeatmap() {
        if (!this.heatmapChart) return;
        
        const now = new Date();
        const data = this.heatmapChart.data.datasets[0].data;
        
        // Add current minute's attack count
        const currentMinute = new Date(now.getFullYear(), now.getMonth(), now.getDate(), now.getHours(), now.getMinutes());
        const existingPoint = data.find(point => point.x.getTime() === currentMinute.getTime());
        
        if (existingPoint) {
            existingPoint.y += 1;
        } else {
            data.push({
                x: currentMinute,
                y: 1
            });
        }
        
        // Keep only last 60 minutes of data
        const oneHourAgo = new Date(now.getTime() - 3600000);
        this.heatmapChart.data.datasets[0].data = data.filter(point => point.x > oneHourAgo);
        this.heatmapChart.update();
    }

    updateGeoData(attack) {
        const geo = this.geoData.get(attack.source_ip);
        if (geo) {
            // Update geographical attack visualization
            this.updateWorldMap(geo, attack);
        }
    }

    playAttackSound() {
        if (this.sounds.newAttack && document.getElementById('soundEnabled')?.checked) {
            this.sounds.newAttack.play().catch(() => {});
        }
    }

    playDefenseSound() {
        if (this.sounds.defensiveAction && document.getElementById('soundEnabled')?.checked) {
            this.sounds.defensiveAction.play().catch(() => {});
        }
    }

    showNotification(title, body) {
        if ('Notification' in window && Notification.permission === 'granted') {
            new Notification(title, {
                body: body,
                icon: '/static/favicon.ico',
                badge: '/static/badge.png'
            });
        }
    }

    triggerHighPriorityAlert(message) {
        // Visual alert
        const alertDiv = document.createElement('div');
        alertDiv.className = 'high-priority-alert';
        alertDiv.innerHTML = `
            <i class="fas fa-exclamation-triangle"></i>
            <strong>HIGH PRIORITY ALERT</strong><br>
            ${message}
        `;
        document.body.appendChild(alertDiv);
        
        setTimeout(() => {
            alertDiv.remove();
        }, 5000);
        
        // Audio alert
        this.playAlarmSound();
        
        // Browser notification
        this.showNotification('HIGH PRIORITY ALERT', message);
    }

    playAlarmSound() {
        // Create alarm sound
        const audioContext = new (window.AudioContext || window.webkitAudioContext)();
        const oscillator = audioContext.createOscillator();
        const gainNode = audioContext.createGain();
        
        oscillator.connect(gainNode);
        gainNode.connect(audioContext.destination);
        
        oscillator.frequency.setValueAtTime(800, audioContext.currentTime);
        oscillator.frequency.setValueAtTime(400, audioContext.currentTime + 0.5);
        
        gainNode.gain.setValueAtTime(0.3, audioContext.currentTime);
        gainNode.gain.exponentialRampToValueAtTime(0.01, audioContext.currentTime + 1);
        
        oscillator.start(audioContext.currentTime);
        oscillator.stop(audioContext.currentTime + 1);
    }

    quickBlock() {
        const lastAttack = this.attackHistory[this.attackHistory.length - 1];
        if (lastAttack) {
            const ip = lastAttack.source_ip;
            if (confirm(`Quick block ${ip}?`)) {
                this.blockIP(ip, 'Quick block via keyboard shortcut');
            }
        }
    }

    blockIP(ip, reason) {
        fetch('/api/manual_block', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ ip: ip, reason: reason })
        })
        .then(response => response.json())
        .then(data => {
            this.showNotification('Block Action', data.message);
        });
    }

    refreshData() {
        location.reload();
    }

    exportData() {
        const data = {
            attacks: this.attackHistory,
            defenses: this.defenseHistory,
            timestamp: new Date().toISOString()
        };
        
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `nosleep-ops-data-${new Date().toISOString().slice(0, 10)}.json`;
        a.click();
        URL.revokeObjectURL(url);
    }

    toggleFullscreen() {
        if (!document.fullscreenElement) {
            document.documentElement.requestFullscreen();
        } else {
            document.exitFullscreen();
        }
    }

    emergencyMode() {
        document.body.classList.toggle('emergency-mode');
        
        if (document.body.classList.contains('emergency-mode')) {
            this.showNotification('Emergency Mode', 'Emergency mode activated');
        }
    }
}

// Initialize advanced monitoring
const attackMonitor = new AttackMonitor();

// Export for global access
window.attackMonitor = attackMonitor; 