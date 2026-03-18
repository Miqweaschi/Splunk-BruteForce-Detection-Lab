# SSH Brute Force Monitoring con Splunk su Parrot OS

## Descrizione

Questa guida documenta la configurazione di un sistema di monitoraggio per rilevare attacchi brute force su SSH usando Splunk su Parrot OS.

---

## Requisiti

- Parrot OS (VirtualBox)
- Splunk installato in `/opt/splunk`

---

## Setup iniziale — avvio dei servizi

### 1. Avviare Splunk

```
sudo /opt/splunk/bin/splunk start --run-as-root
```

Interfaccia web disponibile su: `http://localhost:8000`

### 2. Avviare SSH

```
sudo systemctl start ssh
sudo systemctl enable ssh
```

### 3. Installare rsyslog

rsyslog non è installato di default su Parrot OS. È necessario per scrivere i log in formato testo leggibile da Splunk.

```
sudo apt update && sudo apt install rsyslog -y
sudo systemctl enable rsyslog
sudo systemctl start rsyslog
```

---

## Configurazione Splunk

### 4. Aggiungere il Data Input

1. Vai su **Settings → Data Inputs → Files & Directories → New**
2. Path: `/var/log/auth.log`
3. Sourcetype: `linux_secure`
4. Index: `main`
5. Salva

### 6. Verificare che i dati arrivino

```
index=main source="/var/log/auth.log"
| head 10
```

---

## Query SPL per il rilevamento brute force


### Tentativi falliti per IP

```spl
index=main sourcetype=linux_secure "Failed password"
| rex "from\s+(?<src_ip>[a-f0-9:\.]+)\s+port"
| stats count as tentativi by src_ip
| sort -tentativi
```


## Dashboard

### Creare la dashboard

1. Vai su **Dashboards → Create New Dashboard**
2. Nome: `SSH-BruteForceDetection`
3. Aggiungi pannelli con le query sopra


<img width="1920" height="1020" alt="Dashboard-IMG" src="https://github.com/user-attachments/assets/da445202-ff25-43c0-9f59-a2af7bb30c36" />


```XML
<dashboard version="1.1" theme="dark" refresh="3">
  <label>SSH-BruteForceDetection</label>
  
  <row depends="$show_css$">
    <panel>
      <html>
        <style>
         
          .dashboard-body, .splunk-dashboard, .main-section-body {
            background: #0a0a0c !important;
          }
          
         
          .dashboard-panel { 
            background: #111116 !important; 
            border: 1px solid #00d4ff !important;
            box-shadow: 0 0 8px rgba(0, 212, 255, 0.1) !important;
          }

         
          .table, .table td, .table th {
            background-color: #111116 !important;
            color: #ffffff !important;
            border-bottom: 1px solid #222 !important;
          }
          
          .table th {
            background: #1a1a20 !important;
            color: #00d4ff !important;
            text-transform: uppercase;
          }
          
         
          .dashboard-row:first-child {
            display: none !important;
          }
        </style>
      </html>
    </panel>
  </row>

  <row>
    <panel>
      <title>ATTACCHI</title>
      <single>
        <search>
          <query>index=main sourcetype=linux_secure "Failed password" | stats count</query>
          <earliest>-24h@h</earliest>
          <latest>now</latest>
        </search>
        <option name="colorMode">none</option>
        <option name="rangeColors">["0x00d4ff","0x00d4ff"]</option>
        <option name="underLabel">FAILED LOGINS</option>
        <option name="height">150</option>
      </single>
    </panel>

    <panel>
      <title>LOG SORGENTI</title>
      <table>
        <search>
          <query>
            index=main sourcetype=linux_secure "Failed password" 
            | rex "from\s+(?&lt;src_ip&gt;[a-f0-9:\.]+)\s+port"
            | table src_ip, _raw
          </query>
          <earliest>-24h@h</earliest>
          <latest>now</latest>
        </search>
        <option name="count">5</option>
        <option name="drilldown">none</option>
        <option name="wrap">false</option>
      </table>
    </panel>
  </row>
</dashboard>

```

##Alert

Ho creato un alert basandomi su questa Query:

```SPL
index=main "Failed password"
| rex "from\s+(?<src_ip>[a-f0-9:\.]+)\s+port"
```

Ho impostato l'alert in modo che se rileva 10 tentativi in un minuto invia tramite uno script viene inviato un messaggio ad un bot su telegram.   
per motivi di privacy non posso mostrarvi lo script perchè il bot è personale ma è molto semplice trovare un tutorial su come creare un bot ed usare le sue api su linux.    


<img src="https://github.com/user-attachments/assets/6e45e3fb-4536-49dd-b9e7-63f397615a93" width="50%"/>   


una volta creato lo script, aggiungerlo al path /opt/splunk/bin/scripts/.

## Note

- I log SSH su Parrot OS vengono scritti in `/var/log/auth.log` tramite rsyslog
- Il sourcetype Splunk è `linux_secure` (non `syslog`)
- Il rex usa `[a-f0-9:\.]+` per gestire sia IPv4 (`192.168.1.1`) che IPv6 (`::1`)
- Testare i login falliti da una macchina esterna per avere IP diversi da `127.0.0.1`
