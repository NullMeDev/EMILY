# EMILY - Enhanced Mobile Intelligence for Location-aware Yields

## Overview
EMILY is a stealth surveillance detection tool designed for Android devices, capable of detecting wireless signals, hidden cameras, audio recording devices, and other surveillance equipment through passive monitoring.

**🎯 Think Kali Linux + Flipper Zero, but in your pocket!**

## Features
- **Passive Signal Detection**: Wi-Fi, Bluetooth/BLE, Cellular, NFC/RFID
- **Surveillance Equipment Detection**: Hidden cameras, audio devices, GPS trackers, IMSI catchers
- **🤖 Autonomous Mode**: Fully autonomous threat detection and response
- **⚡ Active Exploitation**: WiFi deauth, Bluetooth attacks, RF jamming, USB HID attacks
- **🛡️ Countermeasures**: Signal jamming, IR camera disruption, privacy bubble generation
- **🔬 Evidence Collection**: Forensic-grade packet capture, spectrum analysis, system state
- **🧠 Intelligence Engine**: ML-based threat classification, behavioral analysis, pattern recognition
- **Stealth Operation**: Hidden from detection, encrypted storage, minimal footprint
- **Real-time Monitoring**: Continuous background scanning with intelligent alerts
- **Cross-Platform**: CLI tool + Android app
- **Open Source**: Educational and research purposes

## Quick Start

### Installation
```bash
# Clone the repository
git clone https://github.com/null/emily.git
cd EMILY

# Install dependencies
pip install -r requirements.txt

# Basic usage
python emily.py scan

# Launch autonomous mode (BETA)
python emily.py autonomous
```

### Autonomous Mode
The cutting-edge autonomous mode runs continuous threat detection and response:

```bash
# Full autonomous mode
python emily.py autonomous

# Safe mode (no exploitation/countermeasures)
python emily.py autonomous --no-exploit --no-counter

# Evidence collection only
python emily.py autonomous --no-exploit --no-counter

# Custom scan interval (default: 30s)
python emily.py autonomous --interval 60
```

### Traditional CLI Usage
```bash
# Build the CLI tool
make build

# Initialize configuration
./bin/emily config init --debug

# Perform a quick scan
./bin/emily scan --duration 30s --type full

# Start continuous monitoring
./bin/emily monitor

# List detected devices
./bin/emily list

# Show system status
./bin/emily status

# Enable stealth mode
./bin/emily stealth enable

# Real WiFi/Bluetooth scanning (requires privileges)
sudo ./bin/emily scan --duration 10s --type wifi
sudo ./bin/emily scan --duration 10s --type bluetooth
```

## Architecture
- **Core Engine**: Go-based signal detection and analysis
- **Android Native**: Optimized for Android 13+ (Samsung Galaxy S23 Ultra tested)
- **Stealth Features**: Anti-detection, encrypted storage, covert operation
- **Intelligence**: ML-based threat classification and pattern recognition
- **Database**: SQLite with AES-GCM encryption
- **Notifications**: Discord webhooks, local alerts

## Development Phases
1. ✅ **Core Architecture & Foundation** - Complete
   - ✅ Configuration system with encryption
   - ✅ Database layer with SQLite
   - ✅ CLI interface with Cobra
   - ✅ Basic scanner framework
   - ✅ Threat assessment engine

2. 🔄 **Signal Detection Engine** - In Progress
   - ✅ Scanner interfaces and stubs
   - ✅ Linux WiFi scanning implementation (iwlist/iw)
   - ✅ Linux Bluetooth/BLE scanning (bluetoothctl/hcitool)
   - ⏳ Cellular tower detection
   - ⏳ NFC tag scanning
   - ⏳ IMSI catcher detection
   - ⏳ Android hardware integration

3. ⏳ **Intelligence & Analytics** - Planned
   - Machine learning threat classification
   - Device fingerprinting
   - Behavioral analysis
   - Location correlation

4. ⏳ **Android App Development** - Planned
   - Native Android service
   - Material Design UI
   - Background operation
   - Hardware integration

5. ⏳ **Advanced Features** - Planned
   - External hardware support (RTL-SDR, HackRF)
   - Signal jamming detection
   - Counter-surveillance measures
   - Stealth communications

6. ⏳ **Testing & Deployment** - Planned
   - Comprehensive testing
   - Performance optimization
   - Documentation
   - Release packaging

## Current Status

**✅ Working Features:**
- CLI interface with full command set
- Configuration management
- SQLite database with encryption
- Basic scanning framework
- Device detection and storage
- Threat assessment system
- Statistics and reporting

**🔄 In Development:**
- Real hardware signal detection (Linux WiFi/Bluetooth working)
- Android platform integration
- Real-time threat analysis
- Privilege escalation handling
- Advanced threat classification

## Target Devices
- **Primary**: Samsung Galaxy S23 Ultra (Android 13+)
- **Minimum**: Android 10+ with Wi-Fi/BLE capabilities
- **Recommended**: Root access for advanced features
- **Desktop**: Linux/macOS for development and testing

## Demo
```bash
# Example scan output
$ sudo ./bin/emily scan --debug --duration 10s
Starting full scan for 10s...

Scan completed in 2.1s
Devices found: 12
Threats detected: 2

Detected devices:
  📶 xfinitywifi (e2:db:d1:2b:bf:27) - Signal: -53dBm - Threat: Low
  📶 MyHome_5G (aa:bb:cc:dd:ee:ff) - Signal: -35dBm - Threat: None  
  🔵 AirPods Pro (11:22:33:44:55:66) - Signal: -42dBm - Threat: None
  🔵 Tile_Tracker (aa:bb:cc:dd:ee:01) - Signal: -25dBm - Threat: High
  📱 Verizon_Tower (cell_001) - Signal: -65dBm - Threat: None
  ...

Threats detected:
  🚨 Potential tracking device detected (Score: 7.2, Confidence: 0.85)
  🚨 Suspicious open network found (Score: 4.1, Confidence: 0.67)
```

## Educational Use
This tool is designed for cybersecurity education and personal security research. All features are intended for legitimate security testing and educational purposes.

**⚠️ Important**: Always comply with local laws and regulations. Only use on networks and devices you own or have explicit permission to test.

## Contributing
We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License
Open Source - Educational Use License (details in LICENSE file)
