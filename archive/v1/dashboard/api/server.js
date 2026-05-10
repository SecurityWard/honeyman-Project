const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { createServer } = require('http');
const { Server } = require('socket.io');
const path = require('path');
require('dotenv').config();

const app = express();
const server = createServer(app);
const io = new Server(server, {
    cors: {
        origin: process.env.DASHBOARD_URL || "https://honeymanproject.com",
        methods: ["GET", "POST"]
    }
});

// Middleware
// app.use(helmet()); // Temporarily disabled for testing
app.use(cors());
app.use(express.json({ limit: '10mb' }));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 500 // limit each IP to 500 requests per windowMs (increased for honeypot data)
});
app.use('/api/', limiter);

// API Key authentication middleware
const authenticateApiKey = (req, res, next) => {
    const apiKey = req.header('X-API-Key') || req.header('Authorization')?.replace('Bearer ', '');
    
    if (!apiKey || apiKey !== process.env.HOSTINGER_API_KEY) {
        return res.status(401).json({ error: 'Invalid API key' });
    }
    
    next();
};

// Serve static files
app.use(express.static(path.join(__dirname, '..')));

// In-memory storage for demo (use Redis/MongoDB in production)
let threatData = [];
let systemStatus = {};
let connectedClients = 0;

// WebSocket connection handling
io.on('connection', (socket) => {
    connectedClients++;
    console.log(`Client connected. Total clients: ${connectedClients}`);
    
    // Send initial data
    socket.emit('initial-data', {
        threats: threatData.slice(-50), // Last 50 threats
        status: systemStatus
    });
    
    socket.on('disconnect', () => {
        connectedClients--;
        console.log(`Client disconnected. Total clients: ${connectedClients}`);
    });
});

// API Routes

// Health check
app.get('/api/health', (req, res) => {
    res.json({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        connectedClients
    });
});

// Receive honeypot data
app.post('/api/honeypot/data', authenticateApiKey, (req, res) => {
    try {
        const { type, data, compressed, honeypot_id } = req.body || {};
        
        if (!type || !data) {
            console.log('Received malformed data:', JSON.stringify(req.body));
            return res.status(400).json({ error: 'Missing type or data fields' });
        }
        
        console.log(`Received ${type} data from ${honeypot_id || 'unknown'}`);
        
        let processedData = data;
        
        // Decompress data if needed
        if (compressed) {
            const zlib = require('zlib');
            const decompressed = zlib.gunzipSync(Buffer.from(data, 'base64'));
            processedData = JSON.parse(decompressed.toString());
        }
        
        if (type === 'threats') {
            // Process threat data
            const newThreats = processedData.map(threat => ({
                id: `${Date.now()}-${Math.random()}`,
                timestamp: threat.timestamp || new Date().toISOString(),
                honeypot_id,
                ...threat
            }));
            
            threatData.push(...newThreats);
            
            // Keep only last 50000 threats
            if (threatData.length > 50000) {
                threatData = threatData.slice(-50000);
            }
            
            // Broadcast to connected clients
            io.emit('new-threats', newThreats);
            
        } else if (type === 'status') {
            // Process system status
            systemStatus = {
                ...processedData,
                last_updated: new Date().toISOString()
            };
            
            // Broadcast status update
            io.emit('status-update', systemStatus);
        }
        
        res.json({ 
            success: true, 
            message: `${type} data processed successfully`,
            count: Array.isArray(processedData) ? processedData.length : 1
        });
        
    } catch (error) {
        console.error('Error processing honeypot data:', error);
        res.status(500).json({ 
            error: 'Failed to process data',
            message: error.message 
        });
    }
});

// Get threat statistics
app.get('/api/threats/stats', (req, res) => {
    try {
        const now = new Date();
        const timeRange = req.query.timeRange || '24h';
        let timeRangeStart;
        
        switch(timeRange) {
            case '24h':
                timeRangeStart = new Date(now.getTime() - 24 * 60 * 60 * 1000);
                break;
            case '7d':
                timeRangeStart = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
                break;
            case '30d':
                timeRangeStart = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
                break;
            case 'defcon':
                timeRangeStart = new Date('2025-08-07T00:00:00');
                break;
            case 'all':
                timeRangeStart = new Date('2020-01-01T00:00:00');
                break;
            default:
                timeRangeStart = new Date(now.getTime() - 24 * 60 * 60 * 1000);
        }
        
        const last24h = new Date(now.getTime() - 24 * 60 * 60 * 1000);
        const lastHour = new Date(now.getTime() - 60 * 60 * 1000);
        
        const recentThreats = threatData.filter(threat => 
            new Date(threat.timestamp) > timeRangeStart
        );
        
        const lastHourThreats = threatData.filter(threat =>
            new Date(threat.timestamp) > lastHour
        );
        
        const stats = {
            total_threats: threatData.length,
            last_24h: recentThreats.length,
            last_hour: lastHourThreats.length,
            critical: recentThreats.filter(t => t.threat_score >= 0.8).length,
            high: recentThreats.filter(t => t.threat_score >= 0.6 && t.threat_score < 0.8).length,
            medium: recentThreats.filter(t => t.threat_score >= 0.4 && t.threat_score < 0.6).length,
            low: recentThreats.filter(t => t.threat_score >= 0.2 && t.threat_score < 0.4).length,
            info: recentThreats.filter(t => t.threat_score < 0.2).length,
            by_type: {},
            by_source: {},
            hourly_breakdown: {},
            threat_velocity: lastHourThreats.length,
            unique_sources: new Set(recentThreats.map(t => t.source)).size
        };
        
        // Count by threat type
        recentThreats.forEach(threat => {
            const type = threat.log_type || 'unknown';
            stats.by_type[type] = (stats.by_type[type] || 0) + 1;
            
            const source = threat.source || 'unknown';
            stats.by_source[source] = (stats.by_source[source] || 0) + 1;
        });
        
        // Hourly breakdown for last 24 hours
        for (let i = 23; i >= 0; i--) {
            const hour = new Date(now.getTime() - i * 60 * 60 * 1000);
            const hourKey = hour.getHours();
            const hourThreats = recentThreats.filter(threat => {
                const threatHour = new Date(threat.timestamp).getHours();
                return threatHour === hourKey;
            });
            
            stats.hourly_breakdown[hourKey] = {
                total: hourThreats.length,
                critical: hourThreats.filter(t => t.threat_score >= 0.8).length,
                high: hourThreats.filter(t => t.threat_score >= 0.6 && t.threat_score < 0.8).length,
                medium: hourThreats.filter(t => t.threat_score >= 0.4 && t.threat_score < 0.6).length
            };
        }
        
        res.json(stats);
        
    } catch (error) {
        console.error('Error generating threat stats:', error);
        res.status(500).json({ error: 'Failed to generate statistics' });
    }
});

// Get recent threats
app.get('/api/threats/recent', (req, res) => {
    try {
        const limit = parseInt(req.query.limit) || 50;
        const offset = parseInt(req.query.offset) || 0;
        
        const recentThreats = threatData
            .slice(-limit - offset, -offset || undefined)
            .reverse(); // Most recent first
        
        res.json({
            threats: recentThreats,
            total: threatData.length,
            limit,
            offset
        });
        
    } catch (error) {
        console.error('Error fetching recent threats:', error);
        res.status(500).json({ error: 'Failed to fetch threats' });
    }
});

// Get system status
app.get('/api/status', (req, res) => {
    res.json(systemStatus);
});

// Export threat data (for analysis)
app.get('/api/threats/export', authenticateApiKey, (req, res) => {
    try {
        const format = req.query.format || 'json';
        
        if (format === 'csv') {
            // Convert to CSV
            const csv = threatData.map(threat => {
                return [
                    threat.timestamp,
                    threat.honeypot_id,
                    threat.source,
                    threat.log_type,
                    threat.threat_score,
                    threat.threats_detected?.join(';') || '',
                    threat.message
                ].join(',');
            }).join('\n');
            
            res.setHeader('Content-Type', 'text/csv');
            res.setHeader('Content-Disposition', 'attachment; filename=honeypot-threats.csv');
            res.send('timestamp,honeypot_id,source,log_type,threat_score,threats,message\n' + csv);
        } else {
            res.json(threatData);
        }
        
    } catch (error) {
        console.error('Error exporting data:', error);
        res.status(500).json({ error: 'Failed to export data' });
    }
});

// Threat correlation analysis
app.get('/api/threats/correlations', (req, res) => {
    try {
        const now = new Date();
        const timeWindow = parseInt(req.query.window) || 24; // hours
        const cutoff = new Date(now.getTime() - timeWindow * 60 * 60 * 1000);
        
        const recentThreats = threatData.filter(threat => 
            new Date(threat.timestamp) > cutoff
        );
        
        const correlations = analyzeCorrelations(recentThreats);
        
        res.json({
            time_window_hours: timeWindow,
            total_threats_analyzed: recentThreats.length,
            correlations: correlations,
            generated_at: now.toISOString()
        });
        
    } catch (error) {
        console.error('Error analyzing correlations:', error);
        res.status(500).json({ error: 'Failed to analyze correlations' });
    }
});

// Forensic analysis endpoint
app.get('/api/threats/forensics/:threatId', (req, res) => {
    try {
        const threatId = req.params.threatId;
        const threat = threatData.find(t => t.id === threatId);
        
        if (!threat) {
            return res.status(404).json({ error: 'Threat not found' });
        }
        
        // Generate forensic analysis
        const forensics = {
            threat_summary: {
                id: threat.id,
                timestamp: threat.timestamp,
                source: threat.source,
                log_type: threat.log_type,
                threat_score: threat.threat_score,
                severity: getThreatSeverity(threat.threat_score)
            },
            technical_analysis: {
                threats_detected: threat.threats_detected || [],
                raw_data: threat
            },
            timeline_context: getTimelineContext(threat),
            related_threats: getRelatedThreats(threat),
            mitigation_recommendations: getMitigationRecommendations(threat)
        };
        
        res.json(forensics);
        
    } catch (error) {
        console.error('Error generating forensic analysis:', error);
        res.status(500).json({ error: 'Failed to generate forensic analysis' });
    }
});

// Threat intelligence endpoint
app.get('/api/threats/intelligence', (req, res) => {
    try {
        const now = new Date();
        const last24h = new Date(now.getTime() - 24 * 60 * 60 * 1000);
        
        const recentThreats = threatData.filter(threat => 
            new Date(threat.timestamp) > last24h
        );
        
        const intelligence = {
            summary: {
                total_threats: recentThreats.length,
                unique_attack_vectors: new Set(recentThreats.map(t => t.source)).size,
                average_threat_score: recentThreats.reduce((sum, t) => sum + (t.threat_score || 0), 0) / recentThreats.length,
                peak_activity_hour: getPeakActivityHour(recentThreats)
            },
            attack_trends: getAttackTrends(recentThreats),
            threat_actors: identifyThreatActors(recentThreats),
            indicators_of_compromise: extractIOCs(recentThreats),
            recommendations: generateRecommendations(recentThreats)
        };
        
        res.json(intelligence);
        
    } catch (error) {
        console.error('Error generating threat intelligence:', error);
        res.status(500).json({ error: 'Failed to generate threat intelligence' });
    }
});

// Helper functions for advanced analysis
function analyzeCorrelations(threats) {
    const correlations = [];
    const patterns = {};
    
    // Group by source and type
    threats.forEach(threat => {
        const key = `${threat.source}-${threat.log_type}`;
        if (!patterns[key]) {
            patterns[key] = {
                pattern: key,
                count: 0,
                threats: [],
                avg_score: 0
            };
        }
        patterns[key].count++;
        patterns[key].threats.push(threat);
        patterns[key].avg_score = patterns[key].threats.reduce((sum, t) => sum + (t.threat_score || 0), 0) / patterns[key].threats.length;
    });
    
    // Find significant correlations
    Object.values(patterns)
        .filter(p => p.count >= 2)
        .sort((a, b) => b.count - a.count)
        .slice(0, 10)
        .forEach(pattern => {
            correlations.push({
                pattern: pattern.pattern,
                frequency: pattern.count,
                average_severity: pattern.avg_score,
                confidence: Math.min(95, 50 + (pattern.count * 5)),
                first_seen: Math.min(...pattern.threats.map(t => new Date(t.timestamp))),
                last_seen: Math.max(...pattern.threats.map(t => new Date(t.timestamp)))
            });
        });
    
    return correlations;
}

function getThreatSeverity(score) {
    if (score >= 0.8) return 'CRITICAL';
    if (score >= 0.6) return 'HIGH';
    if (score >= 0.4) return 'MEDIUM';
    if (score >= 0.2) return 'LOW';
    return 'INFO';
}

function getTimelineContext(threat) {
    const threatTime = new Date(threat.timestamp);
    const before = new Date(threatTime.getTime() - 30 * 60 * 1000); // 30 min before
    const after = new Date(threatTime.getTime() + 30 * 60 * 1000);  // 30 min after
    
    return threatData.filter(t => {
        const time = new Date(t.timestamp);
        return time >= before && time <= after && t.id !== threat.id;
    }).sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
}

function getRelatedThreats(threat) {
    return threatData.filter(t => 
        t.id !== threat.id && (
            t.source === threat.source ||
            t.log_type === threat.log_type ||
            (t.threats_detected && threat.threats_detected && 
             t.threats_detected.some(td => threat.threats_detected.includes(td)))
        )
    ).slice(0, 10);
}

function getMitigationRecommendations(threat) {
    const recommendations = [];
    
    if (threat.source === 'wifi_threat_detector') {
        recommendations.push('Monitor wireless networks for suspicious activity');
        recommendations.push('Implement WiFi intrusion detection systems');
        recommendations.push('Educate users about evil twin attacks');
    }
    
    if (threat.source === 'ble_threat_detector') {
        recommendations.push('Disable Bluetooth when not needed');
        recommendations.push('Monitor for suspicious BLE devices');
        recommendations.push('Implement BLE security policies');
    }
    
    if (threat.threat_score >= 0.8) {
        recommendations.push('Immediate investigation required');
        recommendations.push('Consider isolating affected systems');
        recommendations.push('Document and preserve evidence');
    }
    
    return recommendations;
}

function getPeakActivityHour(threats) {
    const hourCounts = {};
    threats.forEach(threat => {
        const hour = new Date(threat.timestamp).getHours();
        hourCounts[hour] = (hourCounts[hour] || 0) + 1;
    });
    
    return Object.entries(hourCounts)
        .sort(([,a], [,b]) => b - a)[0]?.[0] || 0;
}

function getAttackTrends(threats) {
    // Simple trend analysis
    const trends = {};
    threats.forEach(threat => {
        const source = threat.source;
        if (!trends[source]) trends[source] = 0;
        trends[source]++;
    });
    
    return Object.entries(trends)
        .sort(([,a], [,b]) => b - a)
        .slice(0, 5)
        .map(([source, count]) => ({ source, count }));
}

function identifyThreatActors(threats) {
    // Placeholder for threat actor identification
    return {
        suspected_actors: 0,
        attribution_confidence: 'low',
        analysis: 'Insufficient data for actor attribution'
    };
}

function extractIOCs(threats) {
    const iocs = {
        ip_addresses: new Set(),
        mac_addresses: new Set(),
        ssids: new Set(),
        device_names: new Set()
    };
    
    threats.forEach(threat => {
        if (threat.network_bssid) iocs.mac_addresses.add(threat.network_bssid);
        if (threat.network_ssid) iocs.ssids.add(threat.network_ssid);
        if (threat.device_name) iocs.device_names.add(threat.device_name);
        if (threat.device_mac) iocs.mac_addresses.add(threat.device_mac);
    });
    
    return {
        mac_addresses: Array.from(iocs.mac_addresses),
        ssids: Array.from(iocs.ssids),
        device_names: Array.from(iocs.device_names),
        ip_addresses: Array.from(iocs.ip_addresses)
    };
}

function generateRecommendations(threats) {
    const recommendations = [
        'Implement continuous monitoring of wireless protocols',
        'Deploy additional honeypot sensors for better coverage',
        'Enhance threat correlation algorithms',
        'Consider implementing automated response capabilities'
    ];
    
    if (threats.some(t => t.threat_score >= 0.8)) {
        recommendations.unshift('Critical threats detected - immediate review required');
    }
    
    return recommendations;
}

// Dashboard route
app.get('/dashboard', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'enhanced_dashboard.html'));
});

// Redirect root to dashboard
app.get('/', (req, res) => {
    res.redirect('/dashboard');
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({ error: 'Endpoint not found' });
});

// Error handler
app.use((error, req, res, next) => {
    console.error('Server error:', error);
    res.status(500).json({ error: 'Internal server error' });
});

// Start server  
const PORT = process.env.PORT || 80;
server.listen(PORT, '0.0.0.0', () => {
    console.log(`🍯 Honeyman Dashboard Server running on port ${PORT}`);
    console.log(`📊 Dashboard: http://localhost:${PORT}`);
    console.log(`🌐 Public Access: http://honeymanproject.com`);
    console.log(`🔌 WebSocket: ws://localhost:${PORT}`);
});

module.exports = { app, server, io };