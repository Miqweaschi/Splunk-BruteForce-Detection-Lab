# SSH Brute Force Monitoring con Splunk su Parrot OS

## Descrizione

Questa guida documenta la configurazione di un sistema di monitoraggio per rilevare attacchi brute force su SSH usando Splunk su Parrot OS (macchina virtuale VirtualBox).

---

## Requisiti

- Parrot OS (VirtualBox)
- Splunk installato in `/opt/splunk`
- Connessione di rete attiva

---

## Setup iniziale — avvio dei servizi

### 1. Avviare Splunk

```bash
sudo /opt/splunk/bin/splunk start
```

Interfaccia web disponibile su: `http://localhost:8000`

Per avviare Splunk automaticamente ad ogni riavvio:

```bash
sudo /opt/splunk/bin/splunk enable boot-start
```

### 2. Avviare SSH

```bash
sudo systemctl start ssh
sudo systemctl enable ssh
```

### 3. Avviare VBoxClient (clipboard VirtualBox)

```bash
sudo systemctl enable vboxclipboard
sudo systemctl start vboxclipboard
```

Creare il file di servizio in `/etc/systemd/system/vboxclipboard.service`:

```ini
[Unit]
Description=VirtualBox Clipboard
After=graphical.target

[Service]
ExecStart=/usr/bin/VBoxClient --clipboard
Restart=on-failure

[Install]
WantedBy=graphical.target
```

### 4. Installare rsyslog

rsyslog non è installato di default su Parrot OS. È necessario per scrivere i log in formato testo leggibile da Splunk.

```bash
sudo apt update && sudo apt install rsyslog -y
sudo systemctl enable rsyslog
sudo systemctl start rsyslog
```

---

## Configurazione Splunk

### 5. Aggiungere il Data Input

1. Vai su **Settings → Data Inputs → Files & Directories → New**
2. Path: `/var/log/auth.log`
3. Sourcetype: `linux_secure`
4. Index: `main`
5. Salva

### 6. Verificare che i dati arrivino

```spl
index=main source="/var/log/auth.log"
| head 10
```

---

## Query SPL per il rilevamento brute force

> Nota: il sourcetype è `linux_secure` e il rex usa un pattern che gestisce sia IPv4 che IPv6.

### Tentativi falliti per IP

```spl
index=main sourcetype=linux_secure "Failed password"
| rex "from\s+(?<src_ip>[a-f0-9:\.]+)\s+port"
| stats count as tentativi by src_ip
| sort -tentativi
```

### Brute force attivo — soglia 5 tentativi in 5 minuti

```spl
index=main sourcetype=linux_secure "Failed password"
| rex "from\s+(?<src_ip>[a-f0-9:\.]+)\s+port"
| bin _time span=5m
| stats count as tentativi by src_ip, _time
| where tentativi >= 5
| sort -tentativi
```

### Andamento nel tempo (grafico a linee)

```spl
index=main sourcetype=linux_secure "Failed password"
| timechart span=5m count as tentativi_falliti
```

### Login riusciti dopo fallimenti (possibile breach)

```spl
index=main sourcetype=linux_secure sshd
| stats count(eval(match(_raw,"Failed password"))) AS failed
       count(eval(match(_raw,"Accepted password"))) AS success
       by src_ip
| where failed > 3 AND success > 0
| sort -failed
```

---

## Dashboard

### Creare la dashboard

1. Vai su **Dashboards → Create New Dashboard**
2. Nome: `SSH Brute Force Monitor`
3. Aggiungi pannelli con le query sopra

### Pannelli consigliati

| Pannello | Query | Tipo |
|---|---|---|
| Tentativi nel tempo | timechart | Line chart |
| Top IP attaccanti | stats count by src_ip | Bar chart |
| Brute force attivo | soglia 5 tentativi/5min | Table |
| Breach potenziali | fallimenti + successi | Table |

### Refresh automatico ogni 10 secondi

Modifica il sorgente XML della dashboard:

1. **Edit → Edit Source**
2. Modifica il tag iniziale:

```xml
<dashboard refresh="10">
```

3. Salva

---

## Alert in tempo reale

### Configurare un Alert

1. Esegui questa query nella Search:

```spl
index=main sourcetype=linux_secure "Failed password"
| rex "from\s+(?<src_ip>[a-f0-9:\.]+)\s+port"
| stats count as tentativi by src_ip
| where tentativi >= 10
```

2. Clicca **Save As → Alert**
3. Configura:
   - **Title:** `Brute Force SSH`
   - **Alert type:** `Scheduled` → ogni `1 minute`
   - **Trigger condition:** `Number of Results > 0`
4. In **Trigger Actions** scegli: `Add to Triggered Alerts`, `Send Email` o `Run a Script`
5. Salva

### Visualizzare gli alert scattati

**Activity → Triggered Alerts**

---

## Flusso completo

```
SSH genera log
    ↓
rsyslog scrive in /var/log/auth.log
    ↓
Splunk indicizza (sourcetype: linux_secure)
    ↓
Query SPL rilevano brute force
    ↓
Dashboard aggiornata ogni 10 secondi
    ↓
Alert notifica se tentativi >= 10
```

---

## Note

- I log SSH su Parrot OS vengono scritti in `/var/log/auth.log` tramite rsyslog
- Il sourcetype Splunk è `linux_secure` (non `syslog`)
- Il rex usa `[a-f0-9:\.]+` per gestire sia IPv4 (`192.168.1.1`) che IPv6 (`::1`)
- Testare i login falliti da una macchina esterna per avere IP diversi da `127.0.0.1`
