# 🛡️ ELK Security Log Monitoring

## Security Log Monitoring System for a Small Network Using the ELK Stack with an Alert Dashboard

### نظام مراقبة السجلات الأمنية لشبكة صغيرة باستخدام حزمة ELK مع لوحة تنبيهات

---

> [!CAUTION]
> **⚠️ Lab-Only Configuration / تحذير: بيئة مختبر فقط**
>
> This project uses `xpack.security.enabled=false` and default credentials for simplicity in an **isolated lab environment**. **Never** deploy this configuration on a production or internet-facing system. Always enable authentication, TLS/SSL, and proper access controls in real-world deployments.
>
> هذا المشروع يستخدم `xpack.security.enabled=false` وبيانات اعتماد افتراضية لتبسيط الإعداد في **بيئة مختبر معزولة**. **لا تقم أبداً** بنشر هذا الإعداد على أنظمة إنتاجية أو متصلة بالإنترنت. يجب دائماً تفعيل المصادقة وتشفير TLS/SSL وضوابط الوصول المناسبة في البيئات الحقيقية.

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

The lab environment consists of **4 Virtual Machines** on an isolated internal network:

تتكون بيئة المختبر من **4 أجهزة افتراضية** على شبكة داخلية معزولة:

```
┌─────────────────────────────────────────────────────────────────┐
│                    Isolated Lab Network                         │
│                   الشبكة المعزولة للمختبر                        │
│                                                                 │
│  ┌──────────────────┐          ┌──────────────────────────┐     │
│  │  VM1: ELK Server │          │  VM2: Linux Client       │     │
│  │  (Ubuntu Server)  │◄────────│  (Ubuntu Desktop/Server) │     │
│  │                   │ Filebeat│                           │     │
│  │  - Elasticsearch  │ :5044   │  - Filebeat              │     │
│  │  - Logstash       │         │  - OpenSSH Server        │     │
│  │  - Kibana         │         │  - auth.log / syslog     │     │
│  │                   │         └──────────────────────────┘     │
│  │  Ports:           │                                          │
│  │   9200 (ES)       │         ┌──────────────────────────┐     │
│  │   5044 (Logstash) │◄────────│  VM3: Windows Client     │     │
│  │   5601 (Kibana)   │Winlogbeat│  (Windows 10/11)        │     │
│  │                   │ :5044   │                           │     │
│  └──────────────────┘         │  - Winlogbeat             │     │
│                                │  - RDP Enabled            │     │
│         ▲                      │  - Security Event Logs    │     │
│         │                      └──────────────────────────┘     │
│         │                                                        │
│  ┌──────┴───────────────┐                                       │
│  │  VM4: Kali Attacker  │──────► Attacks SSH (VM2)              │
│  │  (Kali Linux)        │──────► Attacks RDP (VM3)              │
│  │                      │                                       │
│  │  - Nmap              │                                       │
│  │  - Hydra             │                                       │
│  └──────────────────────┘                                       │
└─────────────────────────────────────────────────────────────────┘
```

| VM | Role / الدور | OS | IP (Example) |
|---|---|---|---|
| VM1 | ELK Server / خادم ELK | Ubuntu Server 22.04+ | `192.168.1.10` |
| VM2 | Linux Client / عميل لينكس | Ubuntu Desktop/Server 22.04+ | `192.168.1.11` |
| VM3 | Windows Client / عميل ويندوز | Windows 10/11 | `192.168.1.12` |
| VM4 | Attacker / المهاجم | Kali Linux | `192.168.1.13` |

---

## 📁 Directory Structure / هيكل المجلدات

```
ELK-Security-Log-Monitoring/
│
├── 1-elk-server/
│   ├── docker-compose.yml     # ELK stack containers (ES, Logstash, Kibana)
│   ├── logstash.conf          # Logstash pipeline: Beats input → Grok → ES
│   └── setup_elk.sh           # Automated setup: Docker + sysctl + compose up
│
├── 2-linux-client/
│   └── setup_filebeat.sh      # Install SSH, create testuser, deploy Filebeat
│
├── 3-windows-client/
│   ├── enable_rdp.ps1         # Enable RDP + firewall rule + create 'testuser'
│   └── setup_winlogbeat.ps1   # Deploy Winlogbeat for Windows Event Logs
│
├── 4-kali-attacker/
│   └── attack_simulation.sh   # Nmap scan + Hydra brute-force (SSH & RDP)
│
└── README.md                  # This documentation
```

---

## ✅ Prerequisites / المتطلبات

| Requirement | Details |
|---|---|
| Hypervisor | VirtualBox, VMware, or Hyper-V |
| VM1 RAM | Minimum **4 GB** (recommended 8 GB for ELK) |
| VM2/VM3/VM4 RAM | Minimum **2 GB** each |
| Windows Edition | **Pro, Enterprise, or Education** — Windows 11 **Home** cannot host incoming RDP connections |
| Network Mode | Internal Network or Host-Only (all VMs on the same subnet) |
| Internet Access | Required during initial setup for downloading packages |

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

# Run the setup script (as root) / تشغيل سكربت الإعداد
sudo bash setup_elk.sh
```

Wait for all containers to become healthy (~1-2 minutes):
انتظر حتى تصبح جميع الحاويات جاهزة (~1-2 دقيقة):

```bash
sudo docker ps    # All containers should show "healthy"
```

Verify Elasticsearch is running:
تحقق من تشغيل Elasticsearch:

```bash
curl -u elastic:Admin123!@# http://localhost:9200
```

Access Kibana at: `http://<ELK_SERVER_IP>:5601`

---

### Step 2️⃣ — Linux Client (VM2) / إعداد عميل لينكس

```bash
cd ELK-Security-Log-Monitoring/2-linux-client

# Replace <ELK_IP> with your ELK server IP and optionally set a password
# استبدل <ELK_IP> بعنوان خادم ELK واختيارياً حدد كلمة مرور
sudo bash setup_filebeat.sh 192.168.1.10 YourLabPassword123
```

> [!NOTE]
> If you omit the password argument, it defaults to `ChangeMe_LabOnly`. This is acceptable for an isolated lab.
>
> إذا لم تحدد كلمة المرور، ستكون القيمة الافتراضية `ChangeMe_LabOnly`. هذا مقبول في بيئة مختبر معزولة.

---

### Step 3️⃣ — Windows Client (VM3) / إعداد عميل ويندوز

Open **PowerShell as Administrator**:
افتح **PowerShell كمسؤول**:

```powershell
# Enable Remote Desktop and create the 'testuser' account used by the
# Kali attack script / تفعيل سطح المكتب البعيد وإنشاء حساب 'testuser'
Set-ExecutionPolicy Bypass -Scope Process -Force
.\enable_rdp.ps1 -TestPassword YourLabPassword123

# Install and start Winlogbeat / تثبيت وتشغيل Winlogbeat
.\setup_winlogbeat.ps1 -ElkIP 192.168.1.10
```

> [!NOTE]
> `enable_rdp.ps1` creates a local **`testuser`** account (and adds it to the
> *Remote Desktop Users* group) with the password you pass via `-TestPassword`
> (default `ChangeMe_LabOnly` if omitted). Use the **same password** in Step 4
> so the Hydra RDP brute-force ends in a successful login, just like the SSH
> phase.
>
> ينشئ `enable_rdp.ps1` حساباً محلياً باسم **`testuser`** (ويضيفه إلى مجموعة
> *Remote Desktop Users*) بكلمة المرور التي تمررها عبر `-TestPassword`. استخدم
> **نفس كلمة المرور** في الخطوة 4 حتى ينتهي هجوم RDP بتسجيل دخول ناجح، تماماً
> مثل مرحلة SSH.

---

### Step 4️⃣ — Attack Simulation (VM4 - Kali) / محاكاة الهجمات

```bash
cd ELK-Security-Log-Monitoring/4-kali-attacker

# Run attack simulation / تشغيل محاكاة الهجمات
# Arguments: <LINUX_IP> <WINDOWS_IP> [PASSWORD]
sudo bash attack_simulation.sh 192.168.1.11 192.168.1.12 YourLabPassword123
```

The script will:
- Perform connectivity checks (ping) / فحص الاتصال
- Run Nmap SYN scans on both targets / فحص المنافذ
- Generate a wordlist with ~15 wrong passwords + the correct one at the end / توليد قائمة كلمات مرور
- Run Hydra against SSH (Linux) and RDP (Windows) / تنفيذ هجمات القوة الغاشمة

> [!NOTE]
> The `TARGET_PASSWORD` you pass here must match the `-TestPassword` you used
> in Step 3 for the Windows `testuser` account (and the password used for
> Linux `testuser` in Step 2) so both brute-force phases end in a successful
> login. If your Hydra build has trouble with RDP + NLA, update Hydra/FreeRDP
> to a recent version — current Hydra releases support NLA/CredSSP.

---

### Step 5️⃣ — Kibana Dashboard & Alerts / لوحة المعلومات والتنبيهات

1. Open Kibana: `http://<ELK_SERVER_IP>:5601`
2. Go to **Management → Stack Management → Data Views**
3. Create a data view with pattern: `security-logs-*`
4. Go to **Discover** to explore the logs
5. Use the KQL filters below to detect security events

---

## 🔔 Kibana Alerts & KQL Filters / تنبيهات Kibana واستعلامات KQL

Use these **KQL (Kibana Query Language)** filters in the Discover tab or when creating alert rules:

استخدم استعلامات **KQL** التالية في تبويب Discover أو عند إنشاء قواعد التنبيه:

### Linux SSH Events / أحداث SSH في لينكس

| Event / الحدث | KQL Filter / استعلام KQL | Description / الوصف |
|---|---|---|
| 🔴 Failed SSH Login | `message : "Failed password"` | Detects failed SSH login attempts / كشف محاولات دخول SSH الفاشلة |
| 🟢 Successful SSH Login | `message : "Accepted password"` | Detects successful SSH logins / كشف عمليات دخول SSH الناجحة |

### Windows RDP Events / أحداث RDP في ويندوز

| Event / الحدث | KQL Filter / استعلام KQL | Description / الوصف |
|---|---|---|
| 🔴 Failed RDP Login | `winlog.event_id : "4625"` | Windows failed logon event / حدث فشل تسجيل الدخول في ويندوز |
| 🟢 Successful RDP Login | `winlog.event_id : "4624"` | Windows successful logon event / حدث نجاح تسجيل الدخول في ويندوز |

### Combined Threat Detection / كشف التهديدات المجمع

```
# All failed logins (Linux + Windows) / جميع محاولات الدخول الفاشلة
message : "Failed password" or winlog.event_id : "4625"

# All successful logins (Linux + Windows) / جميع عمليات الدخول الناجحة
message : "Accepted password" or winlog.event_id : "4624"

# All authentication events / جميع أحداث المصادقة
event_type : "ssh_failed_login" or event_type : "ssh_successful_login" or event_type : "windows_failed_login" or event_type : "windows_successful_login"
```

> [!TIP]
> **Creating Alert Rules in Kibana / إنشاء قواعد التنبيه في Kibana:**
>
> 1. Go to **Observability → Alerts → Create Rule** / انتقل إلى Observability → Alerts → Create Rule
> 2. Select **Elasticsearch query** rule type / اختر نوع القاعدة Elasticsearch query
> 3. Use the KQL filters above / استخدم استعلامات KQL أعلاه
> 4. Set threshold (e.g., > 5 failed logins in 5 minutes) / حدد العتبة (مثلاً: أكثر من 5 محاولات فاشلة في 5 دقائق)
> 5. Configure actions (e.g., log, email, webhook) / إعداد الإجراءات (سجل، بريد، webhook)

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
