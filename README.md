# 🛡️ ELK Security Log Monitoring

## Security Log Monitoring System for a Small Network Using the ELK Stack with an Alert Dashboard

### نظام مراقبة السجلات الأمنية لشبكة صغيرة باستخدام حزمة ELK مع لوحة تنبيهات

---

> [!CAUTION]
> **⚠️ Lab-Only Configuration / تحذير: بيئة مختبر فقط**
>
> This project is designed strictly for an **isolated lab network**. While basic authentication (`xpack.security.enabled=true`) is enabled, HTTP TLS/SSL is disabled (`xpack.security.http.ssl.enabled=false` — equivalent in transport risk to `xpack.security.enabled=false`) and default lab credentials (`Admin123!@#` / `ChangeMe_LabOnly`) are included for classroom simplicity. **Never** deploy this configuration or weak lab credentials on a production or internet-facing system. Always enable full TLS/SSL encryption, strong unique secrets, and strict network access controls in real-world deployments.
>
> تم تصميم هذا المشروع حصرياً للعمل في **بيئة مختبر معزولة**. على الرغم من تفعيل المصادقة الأساسية (`xpack.security.enabled=true`)، إلا أن تشفير HTTP TLS/SSL معطل (`xpack.security.http.ssl.enabled=false`) ويتم استخدام كلمات مرور افتراضية للتجربة المخبرية فقط. **لا تقم أبداً** بنشر هذا الإعداد أو كلمات المرور التجريبية على أنظمة إنتاجية أو متصلة بالإنترنت. يجب دائماً تفعيل تشفير TLS/SSL الكامل وضوابط الوصول الصارمة في البيئات الحقيقية.

---

## 📋 Table of Contents / جدول المحتويات

- [Project Overview / نظرة عامة](#-project-overview--نظرة-عامة-على-المشروع)
- [Network Topology / طوبولوجيا الشبكة](#-network-topology--طوبولوجيا-الشبكة)
- [Directory Structure / هيكل المجلدات](#-directory-structure--هيكل-المجلدات)
- [Prerequisites / المتطلبات](#-prerequisites--المتطلبات)
- [Setup Instructions / تعليمات الإعداد](#-setup-instructions--تعليمات-الإعداد)
- [Kibana Alerts & KQL Filters / تنبيهات Kibana](#-kibana-alerts--kql-filters--تنبيهات-kibana-واستعلامات-kql)
- [Technologies Used / التقنيات المستخدمة](#-technologies-used--التقنيات-المستخدمة)
- [License / الرخصة](#-license--الرخصة)

---

## 🎯 Project Overview / نظرة عامة على المشروع

**English:**

This project implements a centralized security log monitoring system for a small network using the **ELK Stack** (Elasticsearch, Logstash, Kibana). The system collects authentication and security logs from Linux and Windows clients, processes them through Logstash, stores them in Elasticsearch, and provides a Kibana dashboard for real-time monitoring and alerting. An attack simulation from a Kali Linux VM validates the detection capabilities.

**العربية:**

يقوم هذا المشروع بتنفيذ نظام مركزي لمراقبة السجلات الأمنية لشبكة صغيرة باستخدام **حزمة ELK** (Elasticsearch, Logstash, Kibana). يجمع النظام سجلات المصادقة والأمان من عملاء Linux وWindows، ويعالجها عبر Logstash، ويخزنها في Elasticsearch، ويوفر لوحة معلومات Kibana للمراقبة والتنبيه في الوقت الفعلي. تتحقق محاكاة الهجمات من جهاز Kali Linux من قدرات الكشف.

---

## 🌐 Network Topology / طوبولوجيا الشبكة

The lab environment consists of **1 Physical Host (Windows)** running the hypervisor and **3 Virtual Machines** on a shared lab network:

تتكون بيئة المختبر من **جهاز مضيف فيزيائي واحد (ويندوز)** يشغل البيئة الافتراضية، و **3 أجهزة افتراضية** على شبكة المختبر المشتركة:

```
┌─────────────────────────────────────────────────────────────────┐
│                    Shared Lab Network                           │
│                   شبكة المختبر المشتركة                          │
│                                                                 │
│  ┌──────────────────┐          ┌──────────────────────────┐     │
│  │  VM1: ELK Server │          │  VM2: Linux Client       │     │
│  │  (Ubuntu Server)  │◄────────│  (Ubuntu 24.04 Target)   │     │
│  │                   │ Filebeat│                           │     │
│  │  - Elasticsearch  │ :5044   │  - Filebeat              │     │
│  │  - Logstash       │         │  - OpenSSH Server        │     │
│  │  - Kibana         │         │  - auth.log / syslog     │     │
│  │                   │         └──────────────────────────┘     │
│  │  Ports:           │                                          │
│  │   9200 (ES)       │         ┌──────────────────────────┐     │
│  │   5044 (Logstash) │◄────────│ Host: Windows Machine    │     │
│  │   5601 (Kibana)   │Winlogbeat│ (Physical Host Running   │     │
│  │                   │ :5044   │  Hypervisor + VMs)       │     │
│  └──────────────────┘         │  - Winlogbeat             │     │
│                                │  - RDP Port 3389 (Scoped) │     │
│         ▲                      │  - 'testrdp' Test User    │     │
│         │                      └──────────────────────────┘     │
│         │                                                        │
│  ┌──────┴───────────────┐                                       │
│  │  VM3: Kali Attacker  │──────► Attacks SSH (VM2: Linux Target) │
│  │  (Kali Linux VM)     │──────► Attacks RDP (Host: Windows RDP)│
│  │                      │                                       │
│  │  - Nmap              │                                       │
│  │  - Hydra             │                                       │
│  └──────────────────────┘                                       │
└─────────────────────────────────────────────────────────────────┘
```

| Node / الجهاز | Role / الدور | Machine Type / نوع الجهاز | OS | IP (Example) |
|---|---|---|---|---|
| **Host** | Windows Client (Target) / عميل ويندوز الهدف | **Physical Host (جهاز مضيف فيزيائي)** | Windows 10/11 Pro/Ent | `192.168.1.12` |
| **VM1** | ELK Server / خادم المراقبة | Virtual Machine (جهاز افتراضي) | Ubuntu Server 24.04 | `192.168.1.10` |
| **VM2** | Linux Client (Target) / عميل لينكس الهدف | Virtual Machine (جهاز افتراضي) | Ubuntu Server 24.04 | `192.168.1.20` |
| **VM3** | Kali Attacker / جهاز المهاجم | Virtual Machine (جهاز افتراضي) | Kali Linux | `192.168.1.13` |

---

## 📁 Directory Structure / هيكل المجلدات

```
ELK-Security-Log-Monitoring/
│
├── 1-elk-server/
│   ├── docker-compose.yml     # ELK stack containers (ES, Logstash, Kibana)
│   ├── logstash.conf          # Logstash pipeline: Beats input → Grok → ES
│   ├── setup_elk.sh           # Automated setup: Docker + sysctl + compose up
│   └── setup_rules.py         # Auto-creates Data View & 3 Kibana Alert Rules
│
├── 2-linux-client/
│   └── setup_filebeat.sh      # Install SSH/rsyslog, create testuser, deploy Filebeat
│
├── 3-windows-client/
│   ├── enable_rdp.ps1         # Enable RDP + start TermService + scoped firewall + create 'testrdp'
│   ├── disable_rdp.ps1        # Post-demo teardown: disable RDP + close port + delete account
│   └── setup_winlogbeat.ps1   # Deploy Winlogbeat for Windows Event Logs
│
├── 4-kali-attacker/
│   └── attack_simulation.sh   # Nmap scan + Hydra brute-force (SSH & RDP)
│
├── LICENSE                    # MIT License
└── README.md                  # This documentation
```

---

## ✅ Prerequisites / المتطلبات

| Requirement / المتطلب | Details / التفاصيل |
|---|---|
| **Physical Host** | Windows 10/11 **Pro, Enterprise, or Education** (Runs Hypervisor; Home edition cannot accept incoming RDP) |
| **Physical Host RAM** | Minimum **16 GB** recommended (Hosts OS + Hypervisor + all 3 VMs) |
| **VM1 (ELK Server) RAM** | Minimum **4 GB** (recommended 6–8 GB for Elasticsearch/Kibana) |
| **VM2 (Linux Client) RAM**| Minimum **2 GB** |
| **VM3 (Kali Attacker) RAM**| Minimum **2 GB** |
| **Hypervisor** | VMware Workstation, VirtualBox, or Hyper-V |
| **Network Mode** | Bridged or Host-Only (Host and all 3 VMs must be reachable on the same subnet) |
| **Internet Access** | Required during initial setup for downloading packages/Docker images |

---

## 🚀 Setup Instructions / تعليمات الإعداد

> [!IMPORTANT]
> Follow the execution order below. Each step depends on the previous one.
>
> اتبع ترتيب التنفيذ أدناه. كل خطوة تعتمد على الخطوة السابقة.

### Step 1️⃣ — ELK Server (VM1) / إعداد خادم ELK

```bash
# Clone the repository / استنساخ المستودع
git clone https://github.com/Sajad-Riyadh/ELK-Security-Log-Monitoring.git
cd ELK-Security-Log-Monitoring/1-elk-server

# Run the interactive setup script / تشغيل سكربت الإعداد التفاعلي
sudo bash setup_elk.sh

# Or provide custom credentials directly / أو حدد بياناتك مباشرة:
# sudo bash setup_elk.sh [USERNAME] [PASSWORD]
# Example: sudo bash setup_elk.sh admin 'MyCustomPassword123!'
```

Wait for all containers to become healthy (~1-2 minutes):
انتظر حتى تصبح جميع الحاويات جاهزة (~1-2 دقيقة):

```bash
sudo docker ps    # Elasticsearch should show "(healthy)"
```

Verify Elasticsearch is running:
تحقق من تشغيل Elasticsearch:

```bash
curl -u elastic:'Admin123!@#' http://localhost:9200
```

Access Kibana at: `http://<ELK_SERVER_IP>:5601`

---

### Step 2️⃣ — Linux Client (VM2) / إعداد عميل لينكس

```bash
cd ELK-Security-Log-Monitoring/2-linux-client

# Replace <ELK_IP> with your ELK server IP and optionally set a password for 'testuser'
# استبدل <ELK_IP> بعنوان خادم ELK واختيارياً حدد كلمة مرور للمستخدم testuser
sudo bash setup_filebeat.sh 192.168.1.10 'YourLabPassword123'
```

> [!NOTE]
> If you omit the password argument, it defaults to `ChangeMe_LabOnly`. Use the exact same password across Step 2, Step 3, and Step 4.
>
> إذا لم تحدد كلمة المرور، ستكون القيمة الافتراضية `ChangeMe_LabOnly`. استخدم نفس كلمة المرور في الخطوات 2 و3 و4.

---

### Step 3️⃣ — Windows Host Client (Physical Machine) / إعداد عميل ويندوز (الجهاز المضيف)

> [!WARNING]
> **Physical Host Security Notice / تنبيه أمني للجهاز المضيف:**
> - The Windows machine is the **physical host running the hypervisor / VMs** (not a virtual machine).
> - For host security, `enable_rdp.ps1` creates a dedicated, **unprivileged local test account (`testrdp`)** restricted strictly to the **Remote Desktop Users** group (never granted Administrator rights) and ensures the `TermService` daemon is running.
> - **Firewall Scoping**: Always pass `-KaliIP <KALI_IP>` so Windows Firewall port 3389 is opened **strictly for the Kali VM's IP address** rather than the entire local network.
> - **Post-Demo Teardown**: Once your demo is finished, run `.\disable_rdp.ps1` as Administrator to immediately disable RDP in the registry, close port 3389, and delete the `testrdp` account.
>
> **ملاحظة أمنية هامة**: جهاز ويندوز هو **الجهاز الفيزيائي المضيف** الذي يشغل البيئة الافتراضية. لأمان جهازك، يقوم سكربت `enable_rdp.ps1` بإنشاء حساب تجريبي مقيد (`testrdp`) ضمن مجموعة مستخدمي سطح المكتب البعيد فقط وتشغيل خدمة `TermService`. يجب دائماً حصر جدار الحماية بعنوان IP الخاص بمهاجم Kali فقط عبر الخيار `-KaliIP`، وتشغيل سكربت `disable_rdp.ps1` فور انتهاء العرض لإغلاق المنفذ وحذف الحساب التجريبي.

Open **PowerShell as Administrator**:
افتح **PowerShell كمسؤول**:

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force

# 1. Enable RDP, ensure TermService is running, create 'testrdp', and scope firewall to Kali IP
# تفعيل RDP وتشغيل الخدمة وإنشاء حساب testrdp المقيد وحصر جدار الحماية بـ Kali IP
.\enable_rdp.ps1 -TestPassword 'YourLabPassword123' -KaliIP '192.168.1.13'

# 2. Install and start Winlogbeat (ships Event IDs 4624 & 4625 to Logstash)
# تثبيت وتشغيل Winlogbeat لإرسال سجلات تسجيل الدخول إلى Logstash
.\setup_winlogbeat.ps1 -ElkIP 192.168.1.10

# -------------------------------------------------------------------------
# Post-Demo Teardown / تنظيف النظام بعد انتهاء العرض:
# Run this script when finished to disable RDP, close port 3389, and delete 'testrdp':
# .\disable_rdp.ps1
# -------------------------------------------------------------------------
```

---

### Step 4️⃣ — Attack Simulation (Kali VM) / محاكاة الهجمات (كالي لينكس)

```bash
cd ELK-Security-Log-Monitoring/4-kali-attacker

# Run attack simulation passing the SAME target password set in Steps 2 & 3:
# تشغيل محاكاة الهجمات بتمرير نفس كلمة المرور المحددة في الخطوتين 2 و3:
sudo bash attack_simulation.sh 192.168.1.20 192.168.1.12 'YourLabPassword123'

# Or run interactively (defaults to ChangeMe_LabOnly if Enter is pressed):
# sudo bash attack_simulation.sh 192.168.1.20 192.168.1.12
```

The script will:
- Verify root privileges and required tools (`nmap`, `hydra`) / التحقق من الصلاحيات والأدوات
- Perform connectivity checks (ping) / فحص الاتصال
- Run Nmap SYN scans (`-sS`) on both targets / فحص المنافذ
- Generate a temporary wordlist (`/tmp/lab_wordlist.txt`) with 15 wrong passwords + the correct target password at the end (auto-deleted on exit) / توليد قائمة كلمات مرور تنتهي بكلمة المرور الصحيحة
- Run Hydra against SSH (`testuser` on Linux) and RDP (`testrdp` on Windows) / تنفيذ هجمات القوة الغاشمة

---

### Step 5️⃣ — Kibana Dashboard & Alerts / لوحة المعلومات والتنبيهات

`setup_elk.sh` automatically invokes `setup_rules.py` to create the **`security-logs-*` Data View** and the **3 Observability Alert Rules**.

1. Open Kibana: `http://<ELK_SERVER_IP>:5601`
2. Go to **Discover** and select the `security-logs-*` data view (or create it manually under **Management → Stack Management → Data Views** if needed)
3. Go to **Observability → Alerts** (`http://<ELK_SERVER_IP>:5601/app/observability/alerts`) to monitor triggered alerts in real time

---

## 🔔 Kibana Alerts & KQL Filters / تنبيهات Kibana واستعلامات KQL

Use these **KQL (Kibana Query Language)** filters in the Discover tab or when creating alert rules:

استخدم استعلامات **KQL** التالية في تبويب Discover أو عند إنشاء قواعد التنبيه:

### Automated Alert Rules Provisioning / إعداد قواعد التنبيهات تلقائياً

`setup_rules.py` is executed automatically at the end of `setup_elk.sh`, or can be run manually at any time:

```bash
# Run from the ELK server:
cd 1-elk-server
python3 setup_rules.py http://localhost:5601 elastic 'Admin123!@#'
```

Rules provisioned (evaluated every 10 seconds):
1. **🚨 SSH Brute Force Detection**: `message : "Failed password" or event_type : "ssh_failed_login"` (Threshold `> 3` in `5m`)
2. **🚨 Windows RDP Brute Force Detection**: `winlog.event_id : "4625" or event_type : "windows_failed_login"` (Threshold `> 3` in `5m`)
3. **🟢 Successful Login After Attack**: `message : "Accepted password" or event_type : "ssh_successful_login" or winlog.event_id : "4624" or event_type : "windows_successful_login"` (Threshold `> 0` in `5m`)

View active alerts in real-time at:
👉 `http://<SERVER_IP>:5601/app/observability/alerts`

---

### Linux SSH Events / أحداث SSH في لينكس

| Event / الحدث | KQL Filter / استعلام KQL | Description / الوصف |
|---|---|---|
| 🔴 Failed SSH Login | `message : "Failed password" or event_type : "ssh_failed_login"` | Detects failed SSH login attempts / كشف محاولات دخول SSH الفاشلة |
| 🟢 Successful SSH Login | `message : "Accepted password" or event_type : "ssh_successful_login"` | Detects successful SSH logins / كشف عمليات دخول SSH الناجحة |

### Windows RDP Events / أحداث RDP في ويندوز

| Event / الحدث | KQL Filter / استعلام KQL | Description / الوصف |
|---|---|---|
| 🔴 Failed RDP Login | `winlog.event_id : "4625" or event_type : "windows_failed_login"` | Windows failed logon event / حدث فشل تسجيل الدخول في ويندوز |
| 🟢 Successful RDP Login | `winlog.event_id : "4624" or event_type : "windows_successful_login"` | Windows successful logon event / حدث نجاح تسجيل الدخول في ويندوز |

### Combined Threat Detection / كشف التهديدات المجمع

```
# All failed logins (Linux + Windows) / جميع محاولات الدخول الفاشلة
message : "Failed password" or winlog.event_id : "4625"

# All successful logins (Linux + Windows) / جميع عمليات الدخول الناجحة
message : "Accepted password" or winlog.event_id : "4624"

# All authentication events / جميع أحداث المصادقة
event_type : "ssh_failed_login" or event_type : "ssh_successful_login" or event_type : "windows_failed_login" or event_type : "windows_successful_login"
```

---

## 🛠️ Technologies Used / التقنيات المستخدمة

| Technology | Version | Purpose / الغرض |
|---|---|---|
| Elasticsearch | 8.17.0 | Log storage and search engine / محرك تخزين وبحث السجلات |
| Logstash | 8.17.0 | Log processing and parsing / معالجة وتحليل السجلات |
| Kibana | 8.17.0 | Visualization and alerting dashboard / لوحة التصور والتنبيهات |
| Filebeat | 8.x | Linux log shipper / ناقل سجلات لينكس |
| Winlogbeat | 8.17.0 | Windows event log shipper / ناقل سجلات أحداث ويندوز |
| Docker & Docker Compose | Latest | Containerization / الحاويات |
| Nmap | Latest | Network reconnaissance / استطلاع الشبكة |
| Hydra | Latest | Credential testing / اختبار بيانات الاعتماد |

---

## 📄 License / الرخصة

This project is licensed under the **MIT License**. See [LICENSE](LICENSE) for details.

هذا المشروع مرخص بموجب **رخصة MIT**. راجع [LICENSE](LICENSE) للتفاصيل.

---

## 👤 Author / المؤلف

Built as a graduation project demonstrating practical security monitoring with the ELK Stack.

تم بناؤه كمشروع تخرج يوضح المراقبة الأمنية العملية باستخدام حزمة ELK.

---

> [!WARNING]
> **Disclaimer / إخلاء المسؤولية:**
> This project is intended for **educational purposes** in an **isolated lab environment only**. The tools and techniques demonstrated (network scanning, credential testing) should only be used on systems you own or have explicit written permission to test. Unauthorized access to computer systems is illegal.
>
> هذا المشروع مخصص **للأغراض التعليمية** في **بيئة مختبر معزولة فقط**. يجب استخدام الأدوات والتقنيات الموضحة (فحص الشبكة، اختبار بيانات الاعتماد) فقط على الأنظمة التي تملكها أو لديك إذن كتابي صريح لاختبارها. الوصول غير المصرح به إلى أنظمة الكمبيوتر غير قانوني.
