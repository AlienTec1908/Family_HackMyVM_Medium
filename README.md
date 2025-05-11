# Family - HackMyVM (Medium)

![Family.png](Family.png)

## Übersicht

*   **VM:** Family
*   **Plattform:** [HackMyVM](https://hackmyvm.eu/machines/machine.php?vm=Family)
*   **Schwierigkeit:** Medium
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 1. November 2021
*   **Original-Writeup:** https://alientec1908.github.io/Family_HackMyVM_Medium/
*   **Autor:** Ben C.

## Kurzbeschreibung

Das Ziel dieser Challenge war die Kompromittierung der virtuellen Maschine "Family" auf der HackMyVM-Plattform. Der Weg begann mit der Enumeration einer WordPress-Installation, für die durch Brute-Force Administrator-Zugangsdaten (`admin`:`phantom`) gefunden wurden. Durch die Bearbeitung einer Theme-Datei wurde eine PHP-Webshell platziert, die initialen Zugriff als `www-data` ermöglichte. Die erste Rechteausweitung auf den Benutzer `father` erfolgte durch das Auffinden eines Klartext-Passworts in einer lesbaren Datei. Die Eskalation zu `mother` gelang durch das Überschreiben eines Python-Skripts (`/home/mother/check.py`), das von einem Cronjob als `mother` ausgeführt wurde. Von `mother` konnte mittels einer `sudo`-Regel für `valgrind` eine Shell als `baby` erlangt werden. `baby` hatte eine `sudo`-Regel, die `cat` ohne Passwort erlaubte. Damit wurde der private SSH-Schlüssel von `root` ausgelesen. Ein SSH-Login als `root` führte zunächst zu einer eingeschränkten Shell (`command="bash ~/troll.sh"`), die `more` aufrief. Durch einen Shell-Escape in `more` (`!/bin/bash`) wurde schließlich eine vollständige Root-Shell erlangt.

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortungsbewusst.

## Verwendete Tools

*   `arp-scan`
*   `nmap`
*   `gobuster`
*   `wpscan`
*   Web Browser
*   `nc (netcat)`
*   `python`
*   `find`
*   `cat`
*   `su`
*   `wget`
*   `chmod`
*   `pspy64`
*   `echo`
*   `sudo`
*   `valgrind`
*   `ssh`
*   `more`
*   `bash`
*   `ls`
*   Standard Linux-Befehle

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "Family" gliederte sich in folgende Phasen:

1.  **Reconnaissance & Web Enumeration (WordPress):**
    *   IP-Findung mittels `arp-scan` (192.168.2.118), Hostname `family.hmv` in `/etc/hosts` eingetragen.
    *   Portscan mit `nmap` identifizierte Port 22 (SSH) und Port 80 (Apache).
    *   `gobuster` fand das Verzeichnis `/wordpress`.
    *   `wpscan` wurde verwendet, um die WordPress-Instanz zu scannen und durch Brute-Force die Administrator-Zugangsdaten `admin`:`phantom` zu finden.

2.  **WordPress RCE (Initial Access als `www-data`):**
    *   Login in das WordPress-Admin-Panel mit den gefundenen Credentials.
    *   Der Theme-Datei-Editor wurde genutzt, um eine PHP-Webshell (`system($_REQUEST['cmd']);`) in die `404.php`-Datei des aktiven Themes einzufügen.
    *   Über die Webshell wurde eine Netcat-Reverse-Shell als Benutzer `www-data` aufgebaut.

3.  **Privilege Escalation (von `www-data` zu `father`):**
    *   Enumeration als `www-data` ergab die Benutzer `father`, `mother`, `baby`.
    *   Die Datei `/usr/share/perl/5.28.1/perso.txt`, die `father` gehörte, enthielt das Klartext-Passwort `uncrackablepassword`.
    *   Mit `su father` und diesem Passwort wurde zu `father` gewechselt.

4.  **Privilege Escalation (von `father` zu `mother` via Cronjob):**
    *   `pspy64` wurde verwendet, um laufende Prozesse zu überwachen. Es wurde ein Cronjob entdeckt, der als UID `1001` (`mother`) das Skript `python ~/check.py` ausführte.
    *   Das Skript `/home/mother/check.py` wurde mit einem Python-Reverse-Shell-Payload überschrieben.
    *   Beim nächsten Ausführen des Cronjobs wurde der Payload ausgeführt und eine Shell als `mother` erlangt.

5.  **Privilege Escalation (von `mother` zu `baby` zu `root`):**
    *   `sudo -l` für `mother` zeigte, dass sie `sudo -u baby /usr/bin/valgrind /bin/bash` ausführen durfte. Dies wurde genutzt, um eine Shell als `baby` zu erhalten. Die User-Flag wurde gelesen.
    *   `sudo -l` für `baby` zeigte: `(ALL : ALL) NOPASSWD: /usr/bin/cat`.
    *   Mit `sudo cat /root/.ssh/id_rsa` wurde der private SSH-Schlüssel von Root ausgelesen.
    *   Die `authorized_keys`-Datei von Root enthielt eine `command="bash ~/troll.sh"`-Einschränkung. Das Skript `troll.sh` führte `more /root/welcome.txt` aus.
    *   Ein SSH-Login als `root` mit dem extrahierten Schlüssel führte zur Ausführung von `more`. Durch Eingabe von `!/bin/bash` innerhalb von `more` wurde eine interaktive Root-Shell erlangt. Die Root-Flag wurde gelesen.

## Wichtige Schwachstellen und Konzepte

*   **WordPress Brute-Force & RCE:** Schwache Administrator-Zugangsdaten ermöglichten den Login. Die Möglichkeit, Theme-Dateien zu bearbeiten, wurde zur Codeausführung (RCE) genutzt.
*   **Klartext-Passwörter in Dateien:** Ein Passwort für den Benutzer `father` wurde im Klartext in einer lesbaren Datei gefunden.
*   **Unsicherer Cronjob mit beschreibbarem Skript:** Ein Cronjob führte ein Python-Skript aus, das von einem weniger privilegierten Benutzer überschrieben werden konnte, was zur Ausführung von beliebigem Code als der Cronjob-Benutzer (`mother`) führte.
*   **Unsichere `sudo`-Konfigurationen:**
    *   `mother` durfte `valgrind` als `baby` ausführen, was zu einer Shell als `baby` missbraucht wurde.
    *   `baby` durfte `cat` als `root` ausführen, was das Lesen beliebiger Dateien (inkl. SSH-Schlüssel) ermöglichte.
*   **SSH `command` Bypass durch Shell-Escape:** Die `command`-Einschränkung in der `authorized_keys`-Datei wurde umgangen, indem das aufgerufene Programm (`more`) einen eingebauten Mechanismus zum Ausführen von Shell-Befehlen (`!befehl`) besaß.

## Flags

*   **User Flag (`/home/baby/user.txt`):** `Chilatyfile`
*   **Root Flag (`/root/last_flag.txt`):** `Selmorbormir`

## Tags

`HackMyVM`, `Family`, `Medium`, `WordPress`, `WPScan`, `RCE`, `PasswordInFile`, `CronjobExploitation`, `SudoValgrind`, `SudoCat`, `SSHCommandBypass`, `MoreEscape`, `Linux`, `Web`, `Privilege Escalation`
